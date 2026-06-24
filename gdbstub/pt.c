/*
 * gdb stub - Intel Processor Trace support
 *
 * Captures Intel PT data via Linux perf_event_open on each KVM vCPU
 * host thread. Exposes the raw trace data over the GDB remote protocol
 * via Qbtrace and qXfer:btrace:read packets.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/error-report.h"
#include "exec/gdbstub.h"
#include "gdbstub/commands.h"
#include "gdbstub/internals.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "host-cpu.h"
#include "pt.h"

#if defined(CONFIG_LINUX) && defined(I386_CPU_H)
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <inttypes.h>
#include <linux/perf_event.h>

/*
 * Per-vCPU PT state
 */
typedef struct GDBPTVCPUState {
    int perf_fd;
    void *config_page;
    void *aux_buffer;
    size_t aux_size;
    uint64_t last_head;
    bool enabled;
} GDBPTVCPUState;

/*
 * Global PT session state
 */
typedef struct {
    GDBPTVCPUState *vcpu;
    uint64_t buffer_size;
    int pt_event_type;
    bool ptwrite;
    bool event_tracing;
    bool active;
    char cpu_vendor[64];
    int cpu_family;
    int cpu_model;
    int cpu_stepping;
} GDBPTSession;

static GDBPTSession pt_session;

static int read_sysfs_int(const char *path, uint32_t *val)
{
    int ret = -1;
    FILE *f = fopen(path, "r");
    if (f) {
        if (fscanf(f, "%" SCNu32, val) == 1) {
            ret = 0;
        }
        fclose(f);
    }
    return ret;
}

static int gdb_pt_discover_pmu_type(void)
{
    uint32_t type;
    if (read_sysfs_int("/sys/bus/event_source/devices/intel_pt/type", &type)) {
        return -1;
    }
    return (int)type;
}

static int gdb_pt_discover_cap_bit(const char *name)
{
    g_autofree char *path = g_strdup_printf(
        "/sys/bus/event_source/devices/intel_pt/caps/%s", name);
    uint32_t val;
    if (read_sysfs_int(path, &val)) {
        return -1;
    }
    return (int)val;
}

static void gdb_pt_read_cpu_info(void)
{
    host_cpu_vendor_fms(pt_session.cpu_vendor,
                        &pt_session.cpu_family,
                        &pt_session.cpu_model,
                        &pt_session.cpu_stepping);
}

static int gdb_pt_enable_vcpu(CPUState *cpu)
{
    struct perf_event_attr attr = {
        .size = sizeof(attr),
        .exclude_kernel = 1,
        .exclude_hv = 1,
        .exclude_idle = 1,
    };
    struct perf_event_mmap_page *header;
    GDBPTVCPUState *vcpu;
    long ret;
    int fd;

    vcpu = &pt_session.vcpu[cpu->cpu_index];

    attr.type = pt_session.pt_event_type;

    if (pt_session.ptwrite) {
        int bit = gdb_pt_discover_cap_bit("ptw");
        if (bit >= 0) {
            attr.config |= (1ULL << bit);
        }
    }
    if (pt_session.event_tracing) {
        int bit = gdb_pt_discover_cap_bit("event");
        if (bit >= 0) {
            attr.config |= (1ULL << bit);
        }
    }

    fd = syscall(SYS_perf_event_open, &attr, cpu->thread_id,
                 -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    vcpu->perf_fd = fd;

    vcpu->config_page = mmap(NULL, qemu_real_host_page_size(),
                             PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (vcpu->config_page == MAP_FAILED) {
        ret = -errno;
        close(fd);
        return ret;
    }

    header = (struct perf_event_mmap_page *)vcpu->config_page;
    header->aux_offset = header->data_offset + header->data_size;
    header->aux_size = pt_session.buffer_size;

    vcpu->aux_buffer = mmap(NULL, pt_session.buffer_size, PROT_READ,
                            MAP_SHARED, fd, header->aux_offset);
    if (vcpu->aux_buffer == MAP_FAILED) {
        ret = -errno;
        munmap(vcpu->config_page, qemu_real_host_page_size());
        close(fd);
        return ret;
    }

    vcpu->aux_size = pt_session.buffer_size;
    vcpu->last_head = 0;
    vcpu->enabled = true;

    /* perf events start disabled; enable to begin collecting trace data */
    if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
        ret = -errno;
        munmap(vcpu->aux_buffer, pt_session.buffer_size);
        munmap(vcpu->config_page, qemu_real_host_page_size());
        close(fd);
        vcpu->enabled = false;
        return ret;
    }

    return 0;
}

static void gdb_pt_disable_vcpu(CPUState *cpu)
{
    GDBPTVCPUState *vcpu = &pt_session.vcpu[cpu->cpu_index];

    if (!vcpu->enabled) {
        return;
    }

    /* Disable perf event but keep AUX buffer mapped for post-stop reads */
    if (vcpu->perf_fd >= 0) {
        ioctl(vcpu->perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    }

    vcpu->enabled = false;
    /*
     * Keep aux_buffer and config_page mapped so GDB can read trace
     * data after Qbtrace:off.  They are freed in gdb_pt_cleanup_all().
     */
}

static void gdb_pt_free_vcpu_buffers(CPUState *cpu)
{
    GDBPTVCPUState *vcpu = &pt_session.vcpu[cpu->cpu_index];

    if (vcpu->aux_buffer) {
        munmap(vcpu->aux_buffer, vcpu->aux_size);
        vcpu->aux_buffer = NULL;
    }
    if (vcpu->config_page) {
        munmap(vcpu->config_page, qemu_real_host_page_size());
        vcpu->config_page = NULL;
    }
    if (vcpu->perf_fd >= 0) {
        close(vcpu->perf_fd);
        vcpu->perf_fd = -1;
    }

    vcpu->aux_size = 0;
    vcpu->last_head = 0;
}

static const char gdb_pt_hex[] = "0123456789abcdef";

static void gdb_pt_read_vcpu_raw(GString *buf, CPUState *cpu)
{
    GDBPTVCPUState *vcpu = &pt_session.vcpu[cpu->cpu_index];
    struct perf_event_mmap_page *header;
    uint64_t aux_head, avail, old;
    uint8_t *raw_data;
    size_t total;
    size_t i;

    /* Allow reads even after Qbtrace:off (vcpu->enabled == false) as long
     * as the AUX buffer is still mapped.  Perf event DISABLE stops hardware
     * writes, making the data stable for post-stop reads. */
    if (!vcpu->aux_buffer || vcpu->aux_size == 0) {
        return;
    }

    header = (struct perf_event_mmap_page *)vcpu->config_page;
    raw_data = (uint8_t *)vcpu->aux_buffer;
    total = vcpu->aux_size;

    aux_head = qatomic_load_acquire(&header->aux_head);
    old = vcpu->last_head;
    avail = aux_head - old;
    if (avail == 0) {
        return;
    }

    for (i = 0; i < avail; i++) {
        size_t idx = (old + i) & (total - 1);
        uint8_t byte = raw_data[idx];
        if (i > 0) {
            if ((i % 32) == 0) {
                g_string_append_c(buf, '\n');
                g_string_append(buf, "      ");
            } else {
                g_string_append_c(buf, ' ');
            }
        }
        g_string_append_c(buf, gdb_pt_hex[(byte >> 4) & 0xf]);
        g_string_append_c(buf, gdb_pt_hex[byte & 0xf]);
    }

    vcpu->last_head = aux_head;
}

static void gdb_pt_build_btrace_xml(GString *xml, CPUState *cpu)
{
    /* Preallocate for worst-case hex encoding: each AUX byte → "XX " (3 chars),
     * plus newline+indent every 32 lines, plus XML wrappers ~300 bytes. */
    g_autoptr(GString) raw = g_string_sized_new(
        pt_session.buffer_size * 3 + pt_session.buffer_size / 32 * 7 + 300);

    gdb_pt_read_vcpu_raw(raw, cpu);

    g_string_printf(xml,
        "<!DOCTYPE btrace SYSTEM \"btrace.dtd\">\n"
        "<btrace version=\"1.0\">\n"
        "  <pt>\n"
        "    <pt-config>\n"
        "      <cpu vendor=\"%s\" family=\"%d\" model=\"%d\" stepping=\"%d\"/>\n"
        "    </pt-config>\n"
        "    <raw>\n"
        "      %s\n"
        "    </raw>\n"
        "  </pt>\n"
        "</btrace>\n",
        pt_session.cpu_vendor, pt_session.cpu_family,
        pt_session.cpu_model, pt_session.cpu_stepping,
        raw->str);
}

static void gdb_handle_qbtrace_conf_pt_size(GArray *params, void *user_ctx)
{
    if (!params->len) {
        gdb_put_packet("E22");
        return;
    }

    pt_session.buffer_size = gdb_get_cmd_param(params, 0)->val_ull;
    if (pt_session.buffer_size < 4096) {
        pt_session.buffer_size = 4096;
    }
    pt_session.buffer_size = 1ULL << (63 - __builtin_clzll(pt_session.buffer_size));
    if (pt_session.buffer_size < 4096) {
        pt_session.buffer_size = 4096;
    }

    gdb_put_packet("OK");
}

static void gdb_handle_qbtrace_conf_pt_ptwrite(GArray *params, void *user_ctx)
{
    if (!params->len) {
        gdb_put_packet("E22");
        return;
    }

    const char *val = gdb_get_cmd_param(params, 0)->data;
    pt_session.ptwrite = (strcmp(val, "on") == 0);
    gdb_put_packet("OK");
}

static void gdb_handle_qbtrace_conf_pt_event(GArray *params, void *user_ctx)
{
    if (!params->len) {
        gdb_put_packet("E22");
        return;
    }

    const char *val = gdb_get_cmd_param(params, 0)->data;
    pt_session.event_tracing = (strcmp(val, "on") == 0);
    gdb_put_packet("OK");
}

static void gdb_handle_qbtrace_pt(GArray *params, void *user_ctx)
{
    CPUState *cpu;
    int ret;

    if (pt_session.active) {
        gdb_put_packet("OK");
        return;
    }

    /* Free any leftover buffers from a previous session */
    CPU_FOREACH(cpu) {
        gdb_pt_free_vcpu_buffers(cpu);
    }

    pt_session.pt_event_type = gdb_pt_discover_pmu_type();
    if (pt_session.pt_event_type < 0) {
        gdb_put_packet("E.nn");
        return;
    }

    gdb_pt_read_cpu_info();

    CPU_FOREACH(cpu) {
        ret = gdb_pt_enable_vcpu(cpu);
        if (ret) {
            warn_report("gdbstub PT: failed to enable on vCPU %d: %s",
                        cpu->cpu_index, strerror(-ret));
        }
    }

    pt_session.active = true;
    gdb_put_packet("OK");
}

static void gdb_handle_qbtrace_off(GArray *params, void *user_ctx)
{
    CPUState *cpu;

    if (!pt_session.active) {
        gdb_put_packet("OK");
        return;
    }

    CPU_FOREACH(cpu) {
        gdb_pt_disable_vcpu(cpu);
    }

    pt_session.active = false;
    /* Keep AUX buffers readable for GDB's post-stop trace read.
     * Free them in gdb_pt_cleanup_all() or on next Qbtrace:pt. */
    gdb_put_packet("OK");
}

static void gdb_handle_qxfer_btrace_read(GArray *params, void *user_ctx)
{
    unsigned long offset, len;
    size_t total_len;
    g_autoptr(GString) xml = g_string_sized_new(
        pt_session.buffer_size * 3 + pt_session.buffer_size / 32 * 7 + 300);

    if (params->len < 3) {
        gdb_put_packet("E22");
        return;
    }

    if (!gdbserver_state.g_cpu) {
        gdb_put_packet("E00");
        return;
    }

    /* Allow reads even after Qbtrace:off (during GDB's post-stop read)
     * as long as the buffer still exists for this vCPU */
    if (!pt_session.vcpu ||
        !pt_session.vcpu[gdbserver_state.g_cpu->cpu_index].aux_buffer) {
        gdb_put_packet("E00");
        return;
    }

    offset = gdb_get_cmd_param(params, 1)->val_ul;
    len = gdb_get_cmd_param(params, 2)->val_ul;

    gdb_pt_build_btrace_xml(xml, gdbserver_state.g_cpu);
    total_len = xml->len;

    if (offset > total_len) {
        gdb_put_packet("E00");
        return;
    }

    if (len > (MAX_PACKET_LENGTH - 5) / 2) {
        len = (MAX_PACKET_LENGTH - 5) / 2;
    }

    if (len < total_len - offset) {
        g_string_assign(gdbserver_state.str_buf, "m");
        gdb_memtox(gdbserver_state.str_buf, xml->str + offset, len);
    } else {
        g_string_assign(gdbserver_state.str_buf, "l");
        gdb_memtox(gdbserver_state.str_buf, xml->str + offset,
                   total_len - offset);
    }

    gdb_put_packet_binary(gdbserver_state.str_buf->str,
                          gdbserver_state.str_buf->len, true);
}

static const GdbCmdParseEntry qxfer_btrace_cmd_desc = {
    .handler = gdb_handle_qxfer_btrace_read,
    .cmd = "Xfer:btrace:read:",
    .cmd_startswith = true,
    .schema = "s:L,L0"
};

static void gdb_handle_qxfer_btrace_conf_read(GArray *params, void *user_ctx)
{
    unsigned long offset, len;
    g_autoptr(GString) xml = g_string_sized_new(256);
    size_t total_len;

    if (params->len < 3) {
        gdb_put_packet("E22");
        return;
    }

    if (pt_session.active) {
        g_string_printf(xml,
            "<!DOCTYPE btrace-conf SYSTEM \"btrace-conf.dtd\">\n"
            "<btrace-conf version=\"1.0\">\n"
            "  <pt>\n"
            "    <size>%" PRIu64 "</size>\n"
            "  </pt>\n"
            "</btrace-conf>\n",
            pt_session.buffer_size);
    } else {
        /* Only report PT config when recording is active.  GDB's
         * remote_btrace_maybe_reopen reads this at connect time and would
         * auto-enable the record target if it sees <pt>, causing a spurious
         * "already being recorded" error when record btrace pt is called. */
        g_string_printf(xml,
            "<!DOCTYPE btrace-conf SYSTEM \"btrace-conf.dtd\">\n"
            "<btrace-conf version=\"1.0\">\n"
            "</btrace-conf>\n");
    }
    total_len = xml->len;

    offset = gdb_get_cmd_param(params, 1)->val_ul;
    len = gdb_get_cmd_param(params, 2)->val_ul;

    if (offset > total_len) {
        gdb_put_packet("E00");
        return;
    }

    if (len > (MAX_PACKET_LENGTH - 5) / 2) {
        len = (MAX_PACKET_LENGTH - 5) / 2;
    }

    if (len < total_len - offset) {
        g_string_assign(gdbserver_state.str_buf, "m");
        gdb_memtox(gdbserver_state.str_buf, xml->str + offset, len);
    } else {
        g_string_assign(gdbserver_state.str_buf, "l");
        gdb_memtox(gdbserver_state.str_buf, xml->str + offset,
                   total_len - offset);
    }

    gdb_put_packet_binary(gdbserver_state.str_buf->str,
                          gdbserver_state.str_buf->len, true);
}

static const GdbCmdParseEntry qxfer_btrace_conf_cmd_desc = {
    .handler = gdb_handle_qxfer_btrace_conf_read,
    .cmd = "Xfer:btrace-conf:read:",
    .cmd_startswith = true,
    .schema = "s:L,L0"
};

static const GdbCmdParseEntry qbtrace_conf_pt_size_cmd_desc = {
    .handler = gdb_handle_qbtrace_conf_pt_size,
    .cmd = "btrace-conf:pt:size:",
    .cmd_startswith = true,
    .schema = "L0"
};

static const GdbCmdParseEntry qbtrace_conf_pt_ptwrite_cmd_desc = {
    .handler = gdb_handle_qbtrace_conf_pt_ptwrite,
    .cmd = "btrace-conf:pt:ptwrite:",
    .cmd_startswith = true,
    .schema = "s0"
};

static const GdbCmdParseEntry qbtrace_conf_pt_event_cmd_desc = {
    .handler = gdb_handle_qbtrace_conf_pt_event,
    .cmd = "btrace-conf:pt:event-tracing:",
    .cmd_startswith = true,
    .schema = "s0"
};

static const GdbCmdParseEntry qbtrace_pt_cmd_desc = {
    .handler = gdb_handle_qbtrace_pt,
    .cmd = "btrace:pt",
};

static const GdbCmdParseEntry qbtrace_off_cmd_desc = {
    .handler = gdb_handle_qbtrace_off,
    .cmd = "btrace:off",
};

bool gdb_pt_is_available(void)
{
    return gdb_pt_discover_pmu_type() >= 0;
}

void gdb_pt_cleanup_all(void)
{
    CPUState *cpu;

    if (!pt_session.vcpu) {
        return;
    }

    CPU_FOREACH(cpu) {
        gdb_pt_free_vcpu_buffers(cpu);
    }

    g_free(pt_session.vcpu);
    pt_session.vcpu = NULL;
    pt_session.active = false;
}

void gdb_pt_register(void)
{
    int num_cpus = gdb_get_max_cpus();
    GPtrArray *queries, *sets;

    memset(&pt_session, 0, sizeof(pt_session));
    pt_session.buffer_size = 64 * 1024;

    pt_session.vcpu = g_new0(GDBPTVCPUState, num_cpus);

    for (int i = 0; i < num_cpus; i++) {
        pt_session.vcpu[i].perf_fd = -1;
    }

    queries = g_ptr_array_new();
    g_ptr_array_add(queries, (void *)&qxfer_btrace_cmd_desc);
    g_ptr_array_add(queries, (void *)&qxfer_btrace_conf_cmd_desc);
    gdb_extend_query_table(queries);
    g_ptr_array_free(queries, FALSE);

    sets = g_ptr_array_new();
    g_ptr_array_add(sets, (void *)&qbtrace_conf_pt_size_cmd_desc);
    g_ptr_array_add(sets, (void *)&qbtrace_conf_pt_ptwrite_cmd_desc);
    g_ptr_array_add(sets, (void *)&qbtrace_conf_pt_event_cmd_desc);
    g_ptr_array_add(sets, (void *)&qbtrace_pt_cmd_desc);
    g_ptr_array_add(sets, (void *)&qbtrace_off_cmd_desc);
    gdb_extend_set_table(sets);
    g_ptr_array_free(sets, FALSE);

    /* Advertise specific btrace features matching gdbserver's format.
     * GDB requires per-format feature names (Qbtrace:pt+) not Qbtrace+. */
    gdb_extend_qsupported_features(
        (char *)";Qbtrace:pt+;Qbtrace:off+;"
        "Qbtrace-conf:pt:size+;"
        "Qbtrace-conf:pt:ptwrite+;"
        "Qbtrace-conf:pt:event-tracing+;"
        "qXfer:btrace:read+;qXfer:btrace-conf:read+");
}

#endif /* CONFIG_LINUX && I386_CPU_H */
