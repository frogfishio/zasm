/* SPDX-FileCopyrightText: 2025 Frogfish */
/* SPDX-License-Identifier: GPL-3.0-or-later */

#include "diag.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

static const char* g_tool = "tool";
static int g_verbose = 0;
static int g_json = 0;
static const char* g_source = NULL;

static const char* path_basename(const char* path) {
	if (!path) return NULL;
	const char* slash = strrchr(path, '/');
	return slash ? (slash + 1) : path;
}

static void json_print_str(FILE* out, const char* s) {
	fputc('"', out);
	for (const unsigned char* p = (const unsigned char*)s; p && *p; p++) {
		switch (*p) {
			case '\\': fputs("\\\\", out); break;
			case '"': fputs("\\\"", out); break;
			case '\n': fputs("\\n", out); break;
			case '\r': fputs("\\r", out); break;
			case '\t': fputs("\\t", out); break;
			default:
				if (*p < 0x20) {
					fprintf(out, "\\u%04x", *p);
				} else {
					fputc(*p, out);
				}
				break;
		}
	}
	fputc('"', out);
}

void diag_set_tool(const char* tool) {
	if (tool && *tool) g_tool = tool;
}

void diag_set_verbose(int on) {
	g_verbose = on ? 1 : 0;
}

void diag_set_json(int on) {
	g_json = on ? 1 : 0;
}

void diag_set_source(const char* path) {
	g_source = path;
}

int diag_is_json(void) {
	return g_json;
}

static int should_emit_level(const char* level) {
	if (g_verbose) return 1;
	return strcmp(level, "error") == 0 || strcmp(level, "warn") == 0;
}

void diag_emitf(const char* level, const char* file, int line, int col, const char* fmt, ...) {
	if (!level || !fmt) return;
	if (!should_emit_level(level)) return;

	const char* path = file ? file : g_source;
	if (col <= 0) col = 1;

	va_list args;
	va_start(args, fmt);

	if (g_json) {
		char msg[1024];
		vsnprintf(msg, sizeof(msg), fmt, args);

		fprintf(stderr, "{\"k\":\"diag\",\"v\":1,\"tool\":");
		json_print_str(stderr, g_tool);
		fprintf(stderr, ",\"level\":");
		json_print_str(stderr, level);
		fprintf(stderr, ",\"message\":");
		json_print_str(stderr, msg);

		if (path) {
			const char* name = path_basename(path);
			fprintf(stderr, ",\"source\":{\"name\":");
			json_print_str(stderr, name ? name : path);
			fprintf(stderr, ",\"path\":");
			json_print_str(stderr, path);
			fprintf(stderr, "}");

			/* Back-compat fields */
			fprintf(stderr, ",\"file\":");
			json_print_str(stderr, path);
		}

		if (line > 0) {
			fprintf(stderr, ",\"range\":{\"start\":{\"line\":%d,\"col\":%d},\"end\":{\"line\":%d,\"col\":%d}}", line, col, line, col);

			/* Back-compat fields */
			fprintf(stderr, ",\"line\":%d", line);
		}

		fprintf(stderr, "}\n");
	} else {
		fprintf(stderr, "%s: %s: ", g_tool, level);
		vfprintf(stderr, fmt, args);
		if (path) {
			fprintf(stderr, " (%s", path);
			if (line > 0) {
				fprintf(stderr, ":%d", line);
				if (col > 0) fprintf(stderr, ":%d", col);
			}
			fprintf(stderr, ")");
		}
		fprintf(stderr, "\n");
	}

	va_end(args);
}

void diag_emit(const char* level, const char* file, int line, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (!level || !fmt) { va_end(args); return; }
	if (!should_emit_level(level)) { va_end(args); return; }

	// Re-route through diag_emitf by formatting once.
	char msg[1024];
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);

	diag_emitf(level, file, line, 1, "%s", msg);
}

