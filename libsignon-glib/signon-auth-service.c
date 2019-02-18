/* vi: set et sw=4 ts=4 cino=t0,(0: */
/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2010 Nokia Corporation.
 * Copyright (C) 2012-2016 Canonical Ltd.
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
 * SECTION:signon-auth-service
 * @title: SignonAuthService
 * @short_description: The authorization service object
 *
 * The #SignonAuthService is the main object in this library.
 */

#include "signon-auth-service.h"
#include "signon-errors.h"
#include "signon-internals.h"
#include "sso-auth-service.h"
#include <gio/gio.h>
#include <glib.h>

/**
 * SignonAuthServiceClass:
 *
 * Opaque struct. Use the accessor functions below.
 */

/**
 * SignonAuthService:
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonAuthService
{
  GObject parent_instance;

  SsoAuthService *proxy;
};

G_DEFINE_TYPE (SignonAuthService, signon_auth_service, G_TYPE_OBJECT);

#define SIGNON_AUTH_SERVICE_PRIV(obj) (SIGNON_AUTH_SERVICE(obj)->priv)

static void
signon_auth_service_init (SignonAuthService *auth_service)
{
    /* Create the proxy */
    auth_service->proxy = sso_auth_service_get_instance ();
}

static void
signon_auth_service_dispose (GObject *object)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (object);

    g_clear_object (&auth_service->proxy);

    G_OBJECT_CLASS (signon_auth_service_parent_class)->dispose (object);
}

static void
signon_auth_service_class_init (SignonAuthServiceClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    object_class->dispose = signon_auth_service_dispose;
}

static void
_signon_auth_service_finish_query_methods (GObject *source_object,
                                           GAsyncResult *res,
                                           gpointer user_data)
{
    SsoAuthService *proxy = NULL;
    GTask *task = (GTask *)user_data;
    gchar **methods_array = NULL;
    GError *error = NULL;

    g_return_if_fail (SSO_IS_AUTH_SERVICE (source_object));
    if (g_task_return_error_if_cancelled (task))
        return;

    proxy = SSO_AUTH_SERVICE (source_object);
    if (sso_auth_service_call_query_methods_finish (proxy, &methods_array, res, &error))
    {
        g_task_return_pointer (task, methods_array, NULL);
    } else {
        g_task_return_error (task, error);
    }
}

static void
_signon_auth_service_finish_query_mechanisms (GObject *source_object,
                                              GAsyncResult *res,
                                              gpointer user_data)
{
    SsoAuthService *proxy = NULL;
    GTask *task = (GTask *)user_data;
    gchar **mechanisms_array = NULL;
    GError *error = NULL;

    g_return_if_fail (SSO_IS_AUTH_SERVICE (source_object));
    if (g_task_return_error_if_cancelled (task))
        return;

    proxy = SSO_AUTH_SERVICE (source_object);
    if (sso_auth_service_call_query_mechanisms_finish (proxy, &mechanisms_array, res, &error))
    {
        g_task_return_pointer (task, mechanisms_array, NULL);
    } else {
        g_task_return_error (task, error);
    }
}

/**
 * signon_auth_service_new:
 *
 * Create a new #SignonAuthService.
 *
 * Returns: an instance of an #SignonAuthService.
 */
SignonAuthService *
signon_auth_service_new ()
{
    return g_object_new (SIGNON_TYPE_AUTH_SERVICE, NULL);
}

/**
 * signon_auth_service_get_methods:
 * @auth_service: a #SignonAuthService
 * @cancellable: (nullable): a #GCancellable or %NULL
 * @callback: a callback to execute upon completion
 * @user_data: closure data for @callback
 *
 * Lists all the available methods.
 *
 * Since: 2.0
 */
void signon_auth_service_get_methods (SignonAuthService *auth_service,
                                      GCancellable *cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
    GTask *task = NULL;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));

    task = g_task_new (auth_service, cancellable, callback, user_data);
    sso_auth_service_call_query_methods (auth_service->proxy, cancellable, _signon_auth_service_finish_query_methods, task);
}

/**
 * signon_auth_service_get_methods_finish:
 * @auth_service: a #SignonAuthService
 * @result: a #GAsyncResult
 * @error: a location for a #GError, or %NULL
 *
 * Completes an asynchronous request to signon_auth_service_get_methods().
 *
 * Returns: (array zero-terminated=1) (transfer full): A list of available
 * methods.
 */
gchar **
signon_auth_service_get_methods_finish (SignonAuthService *auth_service,
                                        GAsyncResult *result,
                                        GError **error)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service), NULL);

    return g_task_propagate_pointer (G_TASK (result), error);
}

/**
 * signon_auth_service_get_methods_sync:
 * @auth_service: a #SignonAuthService
 * @cancellable: (nullable): a #GCancellable or %NULL
 * @error: a location for a #GError, or %NULL
 *
 * Lists all the available methods.
 * This is a blocking version of signon_auth_service_get_methods().
 *
 * Returns: (array zero-terminated=1) (transfer full): A list of available
 * methods.
 *
 * Since: 2.0
 */
gchar **
signon_auth_service_get_methods_sync (SignonAuthService *auth_service,
                                      GCancellable *cancellable,
                                      GError **error)
{
    gchar **methods_array = NULL;

    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service), NULL);

    sso_auth_service_call_query_methods_sync (auth_service->proxy, &methods_array, cancellable, error);

    return methods_array;
}

/**
 * signon_auth_service_get_mechanisms:
 * @auth_service: a #SignonAuthService
 * @method: the name of the method whose mechanisms must be retrieved.
 * @cancellable: (nullable): a #GCancellable or %NULL
 * @callback: a callback to execute upon completion
 * @user_data: closure data for @callback
 *
 * Lists all the available mechanisms.
 *
 * Since: 2.0
 */
void
signon_auth_service_get_mechanisms (SignonAuthService *auth_service,
                                    const gchar *method,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data)
{
    GTask *task = NULL;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));

    task = g_task_new (auth_service, cancellable, callback, user_data);
    sso_auth_service_call_query_mechanisms (auth_service->proxy, method, cancellable, _signon_auth_service_finish_query_mechanisms, task);
}

/**
 * signon_auth_service_get_mechanisms_finish:
 * @auth_service: a #SignonAuthService
 * @result: a #GAsyncResult
 * @error: a location for a #GError, or %NULL
 *
 * Completes an asynchronous request to signon_auth_service_get_mechanisms().
 *
 * Returns: (array zero-terminated=1) (transfer full): A list of available
 * mechanisms.
 */
gchar **
signon_auth_service_get_mechanisms_finish (SignonAuthService *auth_service,
                                           GAsyncResult *result,
                                           GError **error)
{
    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service), NULL);

    return g_task_propagate_pointer (G_TASK (result), error);
}

/**
 * signon_auth_service_get_mechanisms_sync:
 * @auth_service: a #SignonAuthService
 * @method: the name of the method whose mechanisms must be retrieved.
 * @cancellable: (nullable): a #GCancellable or %NULL
 * @error: a location for a #GError, or %NULL
 *
 * Lists all the available mechanisms.
 * This is a blocking version of signon_auth_service_get_mechanisms().
 *
 * Returns: (array zero-terminated=1) (transfer full): A list of available
 * mechanisms.
 *
 * Since: 2.0
 */
gchar **
signon_auth_service_get_mechanisms_sync (SignonAuthService *auth_service,
                                         const gchar *method,
                                         GCancellable *cancellable,
                                         GError **error)
{
    gchar **mechanisms_array = NULL;

    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service), NULL);

    sso_auth_service_call_query_mechanisms_sync (auth_service->proxy, method, &mechanisms_array, cancellable, error);

    return mechanisms_array;
}
