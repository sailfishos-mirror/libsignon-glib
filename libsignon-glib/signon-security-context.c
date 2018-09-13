/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2011-2016 Canonical Ltd.
 *
 * Contact: Alberto Mardegan <alberto.mardegan@canonical.com>
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

/**
 * SECTION:signon-security-context
 * @title: SignonSecurityContext
 * @short_description: Security context for #SignonIdentityInfo.
 *
 * Security context information for a #SignonIdentity.
 */

#include "signon-security-context.h"

#include "signon-internals.h"

G_DEFINE_BOXED_TYPE (SignonSecurityContext, signon_security_context,
                     (GBoxedCopyFunc)signon_security_context_copy,
                     (GBoxedFreeFunc)signon_security_context_free);

SignonSecurityContext *
signon_security_context_new_from_variant (GVariant *variant)
{
    gchar *system_context = NULL;
    gchar *application_context = NULL;
    SignonSecurityContext *ctx;

    g_return_val_if_fail (variant != NULL, NULL);

    g_variant_get (variant, "(ss)", &system_context, &application_context);
    ctx = signon_security_context_new_from_values (system_context, application_context);
    g_free (system_context);
    g_free (application_context);
    return ctx;
}

GVariant *
signon_security_context_to_variant (const SignonSecurityContext *ctx)
{
    g_return_val_if_fail (ctx != NULL, NULL);

    return g_variant_new ("(ss)", ctx->system_context, ctx->application_context);
}

/*
 * Public methods:
 */

/**
 * signon_security_context_new:
 *
 * Creates a new #SignonSecurityContext item.
 *
 * Returns: (transfer full): a new #SignonSecurityContext item.
 */
SignonSecurityContext *
signon_security_context_new (void)
{
    SignonSecurityContext *ctx = g_slice_new0 (SignonSecurityContext);
    ctx->system_context = g_strdup ("");
    ctx->application_context = g_strdup ("");

    return ctx;
}

/**
 * signon_security_context_new_from_values:
 * @system_context: system security context
 * @application_context: application security context
 *
 * Creates a new #SignonSecurityContext item.
 *
 * Returns: (transfer full): a new #SignonSecurityContext item.
 */
SignonSecurityContext *
signon_security_context_new_from_values (const gchar *system_context, const gchar *application_context)
{
    SignonSecurityContext *ctx = signon_security_context_new ();
    if (system_context != NULL)
        signon_security_context_set_system_context (ctx, system_context);

    if (application_context != NULL)
        signon_security_context_set_application_context (ctx, application_context);

    return ctx;
}

/**
 * signon_security_context_free:
 * @ctx: the #SignonSecurityContext.
 *
 * Destroys the given #SignonSecurityContext item.
 */
void
signon_security_context_free (SignonSecurityContext *ctx)
{
    if (ctx == NULL) return;

    g_free (ctx->system_context);
    g_free (ctx->application_context);

    g_slice_free (SignonSecurityContext, ctx);
}

/**
 * signon_security_context_copy:
 * @other: the #SignonSecurityContext.
 *
 * Get a newly-allocated copy of @info.
 *
 * Returns: (transfer full): a copy of the given #SignonIdentityInfo, or %NULL on failure.
 */
SignonSecurityContext *
signon_security_context_copy (const SignonSecurityContext *other)
{
    g_return_val_if_fail (other != NULL, NULL);
    SignonSecurityContext *ctx = signon_security_context_new ();

    signon_security_context_set_system_context (ctx, signon_security_context_get_system_context (other));
    signon_security_context_set_application_context (ctx, signon_security_context_get_application_context (other));

    return ctx;
}

/**
 * signon_security_context_get_application_context:
 * @ctx: the #SignonSecurityContext.
 *
 * Get the application context of @ctx.
 *
 * Returns: the application context.
 */
const gchar *
signon_security_context_get_application_context (const SignonSecurityContext *ctx)
{
    g_return_val_if_fail (ctx != NULL, NULL);

    return ctx->application_context;
}

/**
 * signon_security_context_get_system_context:
 * @ctx: the #SignonSecurityContext.
 *
 * Get the system context of @ctx.
 *
 * Returns: the system context.
 */
const gchar *
signon_security_context_get_system_context (const SignonSecurityContext *ctx)
{
    g_return_val_if_fail (ctx != NULL, NULL);

    return ctx->system_context;
}

/**
 * signon_security_context_set_application_context:
 * @ctx: the #SignonSecurityContext.
 * @application_context: the application context.
 *
 * Sets the application context.
 */
void
signon_security_context_set_application_context (SignonSecurityContext *ctx, const gchar *application_context)
{
    g_return_if_fail (ctx != NULL);

    if (ctx->application_context) g_free (ctx->application_context);

    if (application_context != NULL)
        ctx->application_context = g_strdup (application_context);
    else
        ctx->application_context = g_strdup ("");
}

/**
 * signon_security_context_set_system_context:
 * @ctx: the #SignonSecurityContext.
 * @system_context: the system context.
 *
 * Sets the system context.
 */
void
signon_security_context_set_system_context (SignonSecurityContext *ctx, const gchar *system_context)
{
    g_return_if_fail (ctx != NULL);

    if (ctx->system_context) g_free (ctx->system_context);

    if (system_context != NULL)
        ctx->system_context = g_strdup (system_context);
    else
        ctx->system_context = g_strdup ("");
}
