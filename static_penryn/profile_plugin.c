/* SPDX-License-Identifier: GPL-2.0-or-later
 * Per-thread inline counters: no locks/callbacks in the guest's hot path.
 * Counts instruction attempts, as defined by QEMU's instruction callbacks;
 * a faulting instruction need not retire. No claim of cycle measurement.
 */
#define _POSIX_C_SOURCE 200809L
#include "qemu-plugin.h"
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;
struct row { uint64_t start, end, offset; unsigned kind, id; };
static struct row *rows;
static size_t count, first[3], limit[3];
static unsigned char *binary;
static size_t binary_size;
static uint64_t entry, entry_offset, code_start, bias;
static bool initialized;
static atomic_bool invalid, entry_seen;
static pthread_once_t mapping_once = PTHREAD_ONCE_INIT;
static FILE *output;
static struct qemu_plugin_scoreboard *scores;

static qemu_plugin_u64 counter(size_t index, bool entries)
{
    return (qemu_plugin_u64){scores, (index * 2 + !entries) * sizeof(uint64_t)};
}

static void initialize_mapping(void)
{
    /* entry_code() may describe ld.so after ELF interpreter loading.
     * start_code() retains the main ELF's minimum executable LOAD. */
    uint64_t runtime_start = qemu_plugin_start_code();
    if (runtime_start < code_start) { invalid = true; return; }
    bias = runtime_start - code_start;
    initialized = true;
}

static void translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    (void)id;
    pthread_once(&mapping_once, initialize_mapping);
    if (!initialized) { return; }
    for (size_t i = 0; i < qemu_plugin_tb_n_insns(tb); i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t address = qemu_plugin_insn_vaddr(insn);
        if (address < bias) { continue; }
        address -= bias;
        if (address == entry) {
            unsigned char actual[15];
            size_t length = qemu_plugin_insn_size(insn);
            if (!length || length > sizeof(actual) || entry_offset > binary_size ||
                length > binary_size - entry_offset ||
                qemu_plugin_insn_data(insn, actual, length) != length ||
                memcmp(actual, binary + entry_offset, length)) { invalid = true; }
            else { entry_seen = true; }
        }
        for (unsigned kind = 0; kind < 3; kind++) {
            size_t lo = first[kind], hi = limit[kind];
            while (lo < hi) {
                size_t mid = lo + (hi - lo) / 2;
                if (rows[mid].start <= address) { lo = mid + 1; }
                else { hi = mid; }
            }
            if (lo == first[kind]) { continue; }
            size_t index = lo - 1;
            struct row *r = &rows[index];
            if (address >= r->end) { continue; }
            unsigned char actual[15];
            size_t length = qemu_plugin_insn_size(insn);
            uint64_t offset = r->offset + address - r->start;
            if (!length || length > sizeof(actual) || offset > binary_size ||
                length > binary_size - offset || address + length > r->end ||
                qemu_plugin_insn_data(insn, actual, length) != length ||
                memcmp(actual, binary + offset, length)) {
                invalid = true; continue;
            }
            qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,
                QEMU_PLUGIN_INLINE_ADD_U64, counter(index, false), 1);
            if (address == r->start) {
                qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(insn,
                    QEMU_PLUGIN_INLINE_ADD_U64, counter(index, true), 1);
            }
        }
    }
}

static void finished(qemu_plugin_id_t id, void *userdata)
{
    (void)id; (void)userdata;
    fprintf(output, "PENRYN1 %" PRIx64 " %u\n", bias, invalid || !initialized || !entry_seen);
    for (size_t i = 0; i < count; i++) {
        fprintf(output, "%u %" PRIu64 " %" PRIu64 "\n", rows[i].id,
                qemu_plugin_u64_sum(counter(i, true)),
                qemu_plugin_u64_sum(counter(i, false)));
    }
    fclose(output);
    qemu_plugin_scoreboard_free(scores);
    free(rows); free(binary);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
        const qemu_info_t *info, int argc, char **argv)
{
    if (info->system_emulation || strcmp(info->target_name, "x86_64") ||
        info->version.min > QEMU_PLUGIN_VERSION || info->version.cur < QEMU_PLUGIN_VERSION || argc != 3) {
        fprintf(stderr, "penryn-profile: needs x86_64 user-mode QEMU plugin API 5, and manifest/binary/output arguments\n");
        return 1;
    }
    if (strncmp(argv[0], "manifest=", 9) || strncmp(argv[1], "binary=", 7) ||
        strncmp(argv[2], "output=", 7)) { return 1; }
    FILE *manifest = fopen(argv[0] + 9, "r"), *input = fopen(argv[1] + 7, "rb");
    if (!manifest || !input || fscanf(manifest, "PENRYN1 %" SCNx64 " %" SCNx64 " %" SCNx64 " %zu",
        &entry, &entry_offset, &code_start, &count) != 4 ||
        !count || count > 1000000 || fseek(input, 0, SEEK_END)) { return 1; }
    long size = ftell(input);
    if (size <= 0 || fseek(input, 0, SEEK_SET)) { return 1; }
    binary_size = (size_t)size;
    binary = malloc(binary_size);
    rows = calloc(count, sizeof(*rows));
    if (!binary || !rows || fread(binary, 1, binary_size, input) != binary_size) { return 1; }
    fclose(input);
    unsigned previous_kind = 0;
    uint64_t previous_end = 0;
    for (size_t i = 0; i < count; i++) {
        struct row *r = &rows[i];
        if (fscanf(manifest, "%u %u %" SCNx64 " %" SCNx64 " %" SCNx64,
                   &r->id, &r->kind, &r->start, &r->end, &r->offset) != 5 ||
            r->kind > 2 || r->kind < previous_kind || r->start >= r->end ||
            r->offset > binary_size || r->end - r->start > binary_size - r->offset ||
            (r->kind == previous_kind && r->start < previous_end)) { return 1; }
        previous_kind = r->kind; previous_end = r->end;
    }
    fclose(manifest);
    for (unsigned kind = 0; kind < 3; kind++) {
        first[kind] = limit[kind] = count;
        for (size_t i = 0; i < count; i++) {
            if (rows[i].kind != kind) { continue; }
            if (first[kind] == count) { first[kind] = i; }
            limit[kind] = i + 1;
        }
    }
    output = fopen(argv[2] + 7, "wx");
    if (!output) { return 1; }
    scores = qemu_plugin_scoreboard_new(count * 2 * sizeof(uint64_t));
    qemu_plugin_register_vcpu_tb_trans_cb(id, translate);
    qemu_plugin_register_atexit_cb(id, finished, NULL);
    return 0;
}
