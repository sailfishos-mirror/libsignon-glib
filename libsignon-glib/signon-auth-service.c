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

G_DEFINE_TYPE (SignonAuthService, signon_auth_service, G_TYPE_OBJECT);

struct _SignonAuthServicePrivate
{
    SsoAuthService *proxy;
};

#define SIGNON_AUTH_SERVICE_PRIV(obj) (SIGNON_AUTH_SERVICE(obj)->priv)

static void
signon_auth_service_init (SignonAuthService *auth_service)
{
    SignonAuthServicePrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE (auth_service, SIGNON_TYPE_AUTH_SERVICE,
                                        SignonAuthServicePrivate);
    auth_service->priv = priv;

    /* Create the proxy */
    priv->proxy = sso_auth_service_get_instance ();
}

static void
signon_auth_service_dispose (GObject *object)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (object);
    SignonAuthServicePrivate *priv = auth_service->priv;

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    G_OBJECT_CLASS (signon_auth_service_parent_class)->dispose (object);
}

static void
signon_auth_service_finalize (GObject *object)
{
    G_OBJECT_CLASS (signon_auth_service_parent_class)->finalize (object);
}

static void
signon_auth_service_class_init (SignonAuthServiceClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    g_type_class_add_private (object_class, sizeof (SignonAuthServicePrivate));

    object_class->dispose = signon_auth_service_dispose;
    object_class->finalize = signon_auth_service_finalize;
}

static void
_signon_auth_service_finish_query_methods (GObject *source_object,
                                           GAsyncResult *res,
                                           gpointer user_data)
{
    SsoAuthService *proxy = NULL;
    GTask *task = (GTask *)user_data;
    gchar **methods_array = NULL;
    GList *methods_list = NULL;
    GError *error = NULL;

    g_return_if_fail (SSO_IS_AUTH_SERVICE (source_object));
    if (g_task_return_error_if_cancelled (task))
        return;

    proxy = SSO_AUTH_SERVICE (source_object);
    if (sso_auth_service_call_query_methods_finish (proxy, &methods_array, res, &error))
    {
        int i;
        for (i = 0; methods_array[i] != NULL; i++)
        {
            methods_list = g_list_append (methods_list, methods_array[i]);
        }

        g_task_return_pointer (task, methods_list, NULL);
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
    GList *mechanisms_list = NULL;
    GError *error = NULL;

    g_return_if_fail (SSO_IS_AUTH_SERVICE (source_object));
    if (g_task_return_error_if_cancelled (task))
        return;

    proxy = SSO_AUTH_SERVICE (source_object);
    if (sso_auth_service_call_query_mechanisms_finish (proxy, &mechanisms_array, res, &error))
    {
        int i;
        for (i = 0; mechanisms_array[i] != NULL; i++)
        {
            mechanisms_list = g_list_append (mechanisms_list, mechanisms_array[i]);
        }

        g_task_return_pointer (task, mechanisms_list, NULL);
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
    SignonAuthServicePrivate *priv = NULL;
    GTask *task = NULL;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));

    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);
    task = g_task_new (auth_service, cancellable, callback, user_data);
    sso_auth_service_call_query_methods (priv->proxy, cancellable, _signon_auth_service_finish_query_methods, task);
}

/**
 * signon_auth_service_get_methods_finish:
 * @auth_service: a #SignonAuthService
 * @result: a #GAsyncResult
 * @error: a location for a #GError, or %NULL
 *
 * Completes an asynchronous request to signon_auth_service_get_methods().
 *
 * Returns: (element-type utf8) (transfer full): A list of available methods.
 */
GList *signon_auth_service_get_methods_finish (SignonAuthService *auth_service,
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
 * Returns: (element-type utf8) (transfer full): A list of available methods.
 *
 * Since: 2.0
 */
GList *signon_auth_service_get_methods_sync (SignonAuthService *auth_service,
                                             GCancellable *cancellable,
                                             GError **error)
{
    SignonAuthServicePrivate *priv;
    gchar **methods_array = NULL;
    GList *methods_list = NULL;

    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service), NULL);

    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);
    if (sso_auth_service_call_query_methods_sync (priv->proxy, &methods_array, cancellable, error))
    {
        int i;
        for (i = 0; methods_array[i] != NULL; i++)
        {
            methods_list = g_list_append (methods_list, methods_array[i]);
        }
    }

    return methods_list;
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
void signon_auth_service_get_mechanisms (SignonAuthService *auth_service,
                                         const gchar *method,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
    SignonAuthServicePrivate *priv = NULL;
    GTask *task = NULL;

    g_return_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service));

    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);
    task = g_task_new (auth_service, cancellable, callback, user_data);
    sso_auth_service_call_query_mechanisms (priv->proxy, method, cancellable, _signon_auth_service_finish_query_mechanisms, task);
}

/**
 * signon_auth_service_get_mechanisms_finish:
 * @auth_service: a #SignonAuthService
 * @result: a #GAsyncResult
 * @error: a location for a #GError, or %NULL
 *
 * Completes an asynchronous request to signon_auth_service_get_mechanisms().
 *
 * Returns: (element-type utf8) (transfer full): A list of available mechanisms.
 */
GList *signon_auth_service_get_mechanisms_finish (SignonAuthService *auth_service,
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
 * Returns: (element-type utf8) (transfer full): A list of available mechanisms.
 *
 * Since: 2.0
 */
GList *signon_auth_service_get_mechanisms_sync (SignonAuthService *auth_service,
                                                const gchar *method,
                                                GCancellable *cancellable,
                                                GError **error)
{
    SignonAuthServicePrivate *priv;
    gchar **mechanisms_array = NULL;
    GList *mechanisms_list = NULL;

    g_return_val_if_fail (SIGNON_IS_AUTH_SERVICE (auth_service), NULL);

    priv = SIGNON_AUTH_SERVICE_PRIV (auth_service);
    if (sso_auth_service_call_query_mechanisms_sync (priv->proxy, method, &mechanisms_array, cancellable, error))
    {
        int i;
        for (i = 0; mechanisms_array[i] != NULL; i++)
        {
            mechanisms_list = g_list_append (mechanisms_list, mechanisms_array[i]);
        }
    }

    return mechanisms_list;
}
