/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2018 elementary, Inc
 *
 * Contact: Corentin Noël <corentin@elementary.io>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef _SIGNON_SECURITY_CONTEXT_H_
#define _SIGNON_SECURITY_CONTEXT_H_

#include <glib-object.h>

G_BEGIN_DECLS

/**
 * SignonSecurityContext:
 *
 * Opaque struct. Use the accessor functions below.
 */
typedef struct _SignonSecurityContext SignonSecurityContext;

GType signon_security_context_get_type (void) G_GNUC_CONST;

SignonSecurityContext *signon_security_context_new (void);
SignonSecurityContext *signon_security_context_new_from_values (const gchar *system_context, const gchar *application_context);
void signon_security_context_free (SignonSecurityContext *ctx);

SignonSecurityContext *signon_security_context_copy (const SignonSecurityContext *other);

const gchar *signon_security_context_get_application_context (const SignonSecurityContext *ctx);
const gchar *signon_security_context_get_system_context (const SignonSecurityContext *ctx);

void signon_security_context_set_application_context (SignonSecurityContext *ctx, const gchar *application_context);
void signon_security_context_set_system_context (SignonSecurityContext *ctx, const gchar *system_context);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (SignonSecurityContext, signon_security_context_free);

G_END_DECLS

#endif /* _SIGNON_SECURITY_CONTEXT_H_ */
