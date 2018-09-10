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
 * SECTION:signon-identity
 * @title: SignonIdentity
 * @short_description: Client side presentation of a credential.
 *
 * The #SignonIdentity represents a database entry for a single identity.
 */

#include "signon-identity.h"
#include "signon-auth-session.h"
#include "signon-internals.h"
#include "signon-proxy.h"
#include "signon-errors.h"
#include "sso-auth-service.h"
#include "sso-identity-gen.h"

#define SIGNON_RETURN_IF_CANCELLED(error) \
    if (error != NULL && \
        error->domain == G_IO_ERROR && \
        error->code == G_IO_ERROR_CANCELLED) \
    { \
        g_error_free (error); \
        return; \
    }

static void signon_identity_proxy_if_init (SignonProxyInterface *iface);
static void signon_identity_set_id (SignonIdentity *identity, guint32 id);

G_DEFINE_TYPE_WITH_CODE (SignonIdentity, signon_identity, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (SIGNON_TYPE_PROXY,
                                                signon_identity_proxy_if_init))

enum
{
    PROP_0,
    PROP_ID
};

typedef enum {
    NOT_REGISTERED,
    PENDING_REGISTRATION,
    REGISTERED,
} IdentityRegistrationState;

typedef enum  {
    DATA_UPDATED = 0,
    IDENTITY_REMOVED,
    IDENTITY_SIGNED_OUT
} RemoteIdentityState;

struct _SignonIdentityPrivate
{
    SsoIdentity *proxy;
    SsoAuthService *auth_service_proxy;
    GCancellable *cancellable;

    SignonIdentityInfo *identity_info;

    GSList *sessions;
    IdentityRegistrationState registration_state;

    gboolean removed;
    gboolean signed_out;
    gboolean updated;
    gboolean first_registration;

    guint id;

    guint signal_info_updated;
    guint signal_unregistered;
};

enum {
    SIGNEDOUT_SIGNAL,
    LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

#define SIGNON_IDENTITY_PRIV(obj) (SIGNON_IDENTITY(obj)->priv)

static void identity_check_remote_registration (SignonIdentity *self);
static void identity_store_info_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_store_info_reply (GObject *object, GAsyncResult *res, gpointer userdata);
static void identity_session_object_destroyed_cb (gpointer data, GObject *where_the_session_was);
static void identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_query_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void identity_remove_ready_cb (gpointer object, const GError *error, gpointer user_data);
static void identity_signout_ready_cb (gpointer object, const GError *error, gpointer user_data);

static void identity_process_signout (SignonIdentity *self);
static void identity_process_updated (SignonIdentity *self);
static void identity_process_removed (SignonIdentity *self);

static GQuark
identity_object_quark ()
{
  static GQuark quark = 0;

  if (!quark)
    quark = g_quark_from_static_string ("identity_object_quark");

  return quark;
}

static void
signon_identity_proxy_setup (SignonProxy *proxy)
{
    identity_check_remote_registration (SIGNON_IDENTITY (proxy));
}

static void
signon_identity_proxy_if_init (SignonProxyInterface *iface)
{
    iface->setup = signon_identity_proxy_setup;
}

static void
signon_identity_set_property (GObject *object,
                              guint property_id,
                              const GValue *value,
                              GParamSpec *pspec)
{
    SignonIdentity *self = SIGNON_IDENTITY (object);

    switch (property_id)
    {
    case PROP_ID:
        signon_identity_set_id (self, g_value_get_uint (value));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
signon_identity_get_property (GObject *object,
                              guint property_id,
                              GValue *value,
                              GParamSpec *pspec)
{
    SignonIdentity *self = SIGNON_IDENTITY (object);

    switch (property_id)
    {
    case PROP_ID:
        g_value_set_uint (value, signon_identity_get_id (self));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
        break;
    }
}

static void
signon_identity_init (SignonIdentity *identity)
{
    SignonIdentityPrivate *priv;

    identity->priv = G_TYPE_INSTANCE_GET_PRIVATE (identity,
                                                  SIGNON_TYPE_IDENTITY,
                                                  SignonIdentityPrivate);

    priv = identity->priv;
    priv->auth_service_proxy = sso_auth_service_get_instance();
    priv->cancellable = g_cancellable_new ();
    priv->registration_state = NOT_REGISTERED;

    priv->removed = FALSE;
    priv->signed_out = FALSE;
    priv->updated = FALSE;
    priv->first_registration = TRUE;
}

static void
signon_identity_dispose (GObject *object)
{
    SignonIdentity *identity = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = identity->priv;

    if (priv->cancellable)
    {
        g_cancellable_cancel (priv->cancellable);
        g_object_unref (priv->cancellable);
        priv->cancellable = NULL;
    }

    if (priv->identity_info)
    {
        signon_identity_info_free (priv->identity_info);
        priv->identity_info = NULL;
    }

    g_clear_object (&priv->auth_service_proxy);

    if (priv->proxy)
    {
        g_signal_handler_disconnect (priv->proxy, priv->signal_info_updated);
        g_signal_handler_disconnect (priv->proxy, priv->signal_unregistered);
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    if (priv->sessions)
        g_critical ("SignonIdentity: the list of AuthSessions MUST be empty");

    G_OBJECT_CLASS (signon_identity_parent_class)->dispose (object);
}

static void
signon_identity_finalize (GObject *object)
{
    G_OBJECT_CLASS (signon_identity_parent_class)->finalize (object);
}

static void
signon_identity_class_init (SignonIdentityClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);
    GParamSpec *pspec;

    object_class->set_property = signon_identity_set_property;
    object_class->get_property = signon_identity_get_property;

    pspec = g_param_spec_uint ("id",
                               "Identity ID",
                               "Set/Get Identity ID",
                               0,
                               G_MAXUINT,
                               0,
                               G_PARAM_READWRITE|G_PARAM_CONSTRUCT_ONLY);

    g_object_class_install_property (object_class,
                                     PROP_ID,
                                     pspec);

    g_type_class_add_private (object_class, sizeof (SignonIdentityPrivate));

    /**
     * SignonIdentity::signed-out:
     *
     * Emitted when the identity was signed out.
     */
    signals[SIGNEDOUT_SIGNAL] = g_signal_new("signed-out",
                                    G_TYPE_FROM_CLASS (klass),
                                    G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE | G_SIGNAL_NO_HOOKS,
                                    0 /* class closure */,
                                    NULL /* accumulator */,
                                    NULL /* accu_data */,
                                    g_cclosure_marshal_VOID__VOID,
                                    G_TYPE_NONE /* return_type */,
                                    0);

    object_class->dispose = signon_identity_dispose;
    object_class->finalize = signon_identity_finalize;
}

static void
identity_state_changed_cb (GDBusProxy *proxy,
                           gint state,
                           gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (user_data));
    SignonIdentity *self = SIGNON_IDENTITY (user_data);

    switch (state) {
        case DATA_UPDATED:
            DEBUG ("State changed to DATA_UPDATED");
            identity_process_updated (self);
            break;
        case IDENTITY_REMOVED:
            DEBUG ("State changed to IDENTITY_REMOVED");
            identity_process_removed (self);
            break;
        case IDENTITY_SIGNED_OUT:
            DEBUG ("State changed to IDENTITY_SIGNED_OUT");
            identity_process_signout (self);
            break;
        default:
            g_critical ("wrong state value obtained from signon daemon");
    };
}

static void
identity_remote_object_destroyed_cb(GDBusProxy *proxy,
                                    gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (user_data));
    SignonIdentity *self = SIGNON_IDENTITY (user_data);

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    if (priv->proxy)
    {
        g_object_unref (priv->proxy);
        priv->proxy = NULL;
    }

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    signon_proxy_set_not_ready (self);

    priv->registration_state = NOT_REGISTERED;

    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;

    priv->removed = FALSE;
    priv->signed_out = FALSE;
    priv->updated = FALSE;
}

static void
identity_registered (SignonIdentity *identity,
                     char *object_path, GVariant *identity_data,
                     GError *error)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (identity));

    SignonIdentityPrivate *priv;
    priv = identity->priv;

    g_return_if_fail (priv != NULL);

    if (!error)
    {
        GDBusConnection *connection;
        GDBusProxy *auth_service_proxy;
        const gchar *bus_name;
        GError *proxy_error = NULL;

        DEBUG("%s: %s", G_STRFUNC, object_path);
        /*
         * TODO: as Aurel will finalize the code polishing so we will
         * need to implement the refresh of the proxy to SignonIdentity
         * */
        g_return_if_fail (priv->proxy == NULL);

        auth_service_proxy = (GDBusProxy *)priv->auth_service_proxy;
        connection = g_dbus_proxy_get_connection (auth_service_proxy);
        bus_name = g_dbus_proxy_get_name (auth_service_proxy);

        priv->proxy =
            sso_identity_proxy_new_sync (connection,
                                         G_DBUS_PROXY_FLAGS_NONE,
                                         bus_name,
                                         object_path,
                                         priv->cancellable,
                                         &proxy_error);
        if (G_UNLIKELY (proxy_error != NULL))
        {
            g_warning ("Failed to initialize Identity proxy: %s",
                       proxy_error->message);
            g_clear_error (&proxy_error);
        }

        priv->signal_info_updated =
            g_signal_connect (priv->proxy,
                              "info-updated",
                              G_CALLBACK (identity_state_changed_cb),
                              identity);

        priv->signal_unregistered =
            g_signal_connect (priv->proxy,
                              "unregistered",
                              G_CALLBACK (identity_remote_object_destroyed_cb),
                              identity);

        if (identity_data)
        {
            DEBUG("%s: ", G_STRFUNC);
            priv->identity_info =
                signon_identity_info_new_from_variant (identity_data);
            g_variant_unref (identity_data);
        }

        priv->updated = TRUE;
    }
    else if (error->domain == G_DBUS_ERROR &&
             error->code == G_DBUS_ERROR_SERVICE_UNKNOWN)
    {
        /* This can happen if signond quits and the GDBusProxy is not notified
         * about it -- typically because the main loop was not being run.
         * We try the registration once more.
         */
        if (priv->first_registration)
        {
            DEBUG ("Service unknown; retrying registration");
            g_error_free (error);
            priv->first_registration = FALSE;
            priv->registration_state = NOT_REGISTERED;
            identity_check_remote_registration (identity);
            return;
        }
        else
        {
            g_warning ("%s, second failure: %s", G_STRFUNC, error->message);
        }
    }
    else
        g_warning ("%s: %s", G_STRFUNC, error->message);

    /*
     * execute queued operations or emit errors on each of them
     * */
    priv->registration_state = REGISTERED;

    /*
     * TODO: if we will add a new state for identity: "INVALID"
     * consider emission of another error, like "invalid"
     * */
    signon_proxy_set_ready (identity, identity_object_quark (), error);

    /*
     * as the registration failed we do not
     * request for new registration, but emit
     * same error again and again
     * */
}

/**
 * signon_identity_get_id:
 * @identity: the #SignonIdentity.
 *
 * Get the id of the @identity.
 *
 * Since: 2.0
 *
 * Returns: the id of the #SignonIdentity, or 0 if the identity has not being
 * registered.
 */
guint32
signon_identity_get_id (SignonIdentity *identity)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), 0);
    g_return_val_if_fail (identity->priv != NULL, 0);

    return identity->priv->id;
}

static void
signon_identity_set_id (SignonIdentity *identity, guint32 id)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (identity));
    g_return_if_fail (identity->priv != NULL);

    if (identity->priv->id != id)
    {
        identity->priv->id = id;
        g_object_notify (G_OBJECT (identity), "id");
    }
}

/**
 * signon_identity_get_last_error:
 * @identity: the #SignonIdentity.
 *
 * Get the most recent error that occurred on @identity.
 *
 * Returns: a #GError containing the most recent error, or %NULL on failure.
 */
const GError *
signon_identity_get_last_error (SignonIdentity *identity)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    return signon_proxy_get_last_error (identity);
}

static void
identity_new_cb (GObject *object, GAsyncResult *res,
                 gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    gchar *object_path = NULL;
    GError *error = NULL;

    g_return_if_fail (identity != NULL);
    DEBUG ("%s", G_STRFUNC);

    sso_auth_service_call_register_new_identity_finish (proxy,
                                                        &object_path,
                                                        res,
                                                        &error);
    SIGNON_RETURN_IF_CANCELLED (error);
    identity_registered (identity, object_path, NULL, error);
    g_free (object_path);
}

static void
identity_new_from_db_cb (GObject *object, GAsyncResult *res,
                         gpointer userdata)
{
    SignonIdentity *identity = (SignonIdentity*)userdata;
    SsoAuthService *proxy = SSO_AUTH_SERVICE (object);
    gchar *object_path = NULL;
    GVariant *identity_data;
    GError *error = NULL;

    g_return_if_fail (identity != NULL);
    DEBUG ("%s", G_STRFUNC);

    sso_auth_service_call_get_identity_finish (proxy,
                                               &object_path,
                                               &identity_data,
                                               res,
                                               &error);
    SIGNON_RETURN_IF_CANCELLED (error);
    identity_registered (identity, object_path, identity_data, error);
    g_free (object_path);
}

static void
identity_check_remote_registration (SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    SignonIdentityPrivate *priv = self->priv;

    g_return_if_fail (priv != NULL);

    if (priv->registration_state != NOT_REGISTERED)
        return;

    /* TODO: implement the application security context */
    if (priv->id != 0)
        sso_auth_service_call_get_identity (priv->auth_service_proxy,
                                            priv->id,
                                            "*",
                                            priv->cancellable,
                                            identity_new_from_db_cb,
                                            self);
    else
        sso_auth_service_call_register_new_identity (priv->auth_service_proxy,
                                                     "*",
                                                     priv->cancellable,
                                                     identity_new_cb,
                                                     self);

    priv->registration_state = PENDING_REGISTRATION;
}

/**
 * signon_identity_new_from_db:
 * @id: identity ID.
 *
 * Construct an identity object associated with an existing identity
 * record.
 *
 * Returns: an instance of a #SignonIdentity.
 */
SignonIdentity*
signon_identity_new_from_db (guint32 id)
{
    SignonIdentity *identity;
    DEBUG ("%s %d: %d\n", G_STRFUNC, __LINE__, id);
    if (id == 0)
        return NULL;

    identity = g_object_new (SIGNON_TYPE_IDENTITY, "id", id, NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    g_return_val_if_fail (identity->priv != NULL, NULL);

    identity_check_remote_registration (identity);

    return identity;
}

/**
 * signon_identity_new:
 *
 * Construct new, empty, identity object.
 *
 * Returns: an instance of an #SignonIdentity.
 */
SignonIdentity*
signon_identity_new ()
{
    DEBUG ("%s %d", G_STRFUNC, __LINE__);
    SignonIdentity *identity = g_object_new (SIGNON_TYPE_IDENTITY, NULL);
    g_return_val_if_fail (SIGNON_IS_IDENTITY (identity), NULL);
    g_return_val_if_fail (identity->priv != NULL, NULL);
    identity_check_remote_registration (identity);

    return identity;
}

static void
identity_session_object_destroyed_cb(gpointer data,
                                     GObject *where_the_session_was)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (data));
    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    SignonIdentity *self = SIGNON_IDENTITY (data);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    priv->sessions = g_slist_remove(priv->sessions, (gpointer)where_the_session_was);
    g_object_unref (self);
}

/**
 * signon_identity_create_session:
 * @self: the #SignonIdentity.
 * @method: method.
 * @error: pointer to a location which will receive the error, if any.
 *
 * Creates an authentication session for this identity.
 *
 * Returns: (transfer full): a new #SignonAuthSession.
 */
SignonAuthSession *
signon_identity_create_session(SignonIdentity *self,
                               const gchar *method,
                               GError **error)
{
    g_return_val_if_fail (SIGNON_IS_IDENTITY (self), NULL);

    SignonIdentityPrivate *priv = self->priv;
    g_return_val_if_fail (priv != NULL, NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    if (method == NULL)
    {
        DEBUG ("NULL method as input. Aborting.");
        g_set_error(error,
                    signon_error_quark(),
                    SIGNON_ERROR_UNKNOWN,
                    "NULL input method.");
        return NULL;
    }

    GSList *list = priv->sessions;
    while (list)
    {
        SignonAuthSession *session = SIGNON_AUTH_SESSION (priv->sessions->data);
        const gchar *sessionMethod = signon_auth_session_get_method (session);
        if (g_strcmp0(sessionMethod, method) == 0)
        {
            DEBUG ("Auth Session with method `%s` already created.", method);
            g_set_error (error,
                         signon_error_quark(),
                         SIGNON_ERROR_METHOD_NOT_AVAILABLE,
                         "Authentication session for this method already requested.");
            return NULL;
        }

        list = list->next;
    }

    SignonAuthSession *session = signon_auth_session_new (priv->id,
                                                          method,
                                                          error);
    if (session)
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);
        priv->sessions = g_slist_append(priv->sessions, session);
        g_object_weak_ref (G_OBJECT(session),
                           identity_session_object_destroyed_cb,
                           self);
        /*
         * if you want to delete the identity
         * you MUST delete all authsessions
         * first
         * */
        g_object_ref (self);
        priv->signed_out = FALSE;
    }

    return session;
}

/**
 * signon_identity_store_info:
 * @self: the #SignonIdentity.
 * @info: the #SignonIdentityInfo data to store.
 * @cancellable: (nullable): optional #GCancellable object, %NULL to ignore.
 * @callback: a callback which will be called when the
 * authentication reply is available.
 * @user_data: user data to be passed to the callback.
 *
 * Stores the data from @info into the identity.
 *
 * Since: 2.0
 */
void
signon_identity_store_info (SignonIdentity *self,
                            const SignonIdentityInfo *info,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
    GTask *task = NULL;
    GVariant *info_variant = NULL;

    DEBUG ();
    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    g_return_if_fail (info != NULL);

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_source_tag (task, signon_identity_store_info);
    info_variant = signon_identity_info_to_variant (info);
    g_task_set_task_data (task, g_variant_ref_sink (info_variant), (GDestroyNotify)g_variant_unref);

    signon_proxy_call_when_ready (self,
                                  identity_object_quark(),
                                  identity_store_info_ready_cb,
                                  task);
}

/**
 * signon_identity_store_info_finish:
 * @self: the #SignonIdentity.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to
 * signon_identity_store_info().
 * @error: return location for error, or %NULL.
 *
 * Collect the result of the signon_identity_store_info() operation.
 *
 * Returns: %TRUE if the info has been stored, %FALSE otherwise.
 */
gboolean
signon_identity_store_info_finish (SignonIdentity *self,
                                   GAsyncResult *res,
                                   GError **error)
{
    g_return_val_if_fail (g_task_is_valid (res, self), FALSE);

    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
identity_store_info_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    g_return_if_fail (SIGNON_IS_IDENTITY (object));

    SignonIdentity *self = SIGNON_IDENTITY (object);
    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv != NULL);

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    GTask *task = (GTask *)user_data;
    g_return_if_fail (task != NULL);

    if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        g_task_return_error (task, g_error_copy (error));
        g_object_unref (task);
    }
    else
    {
        g_return_if_fail (priv->proxy != NULL);

        sso_identity_call_store (priv->proxy,
                                 g_task_get_task_data (task),
                                 g_task_get_cancellable (task),
                                 identity_store_info_reply,
                                 task);
    }
}

static void
identity_store_info_reply (GObject *object,
                           GAsyncResult *res,
                           gpointer userdata)
{
    GTask *task = (GTask *)userdata;
    SsoIdentity *proxy = SSO_IDENTITY (object);
    SignonIdentity *self = NULL;
    SignonIdentityPrivate *priv = NULL;
    GError *error = NULL;
    guint id;

    g_return_if_fail (task != NULL);

    self = g_task_get_source_object (task);
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    priv = self->priv;
    if (sso_identity_call_store_finish (proxy, &id, res, &error)) {
        GSList *slist = priv->sessions;

        g_return_if_fail (priv->identity_info == NULL);

        while (slist)
        {
            SignonAuthSession *session = SIGNON_AUTH_SESSION (priv->sessions->data);
            signon_auth_session_set_id (session, id);
            slist = g_slist_next (slist);
        }

        signon_identity_set_id (self, id);

        /*
         * if the previous state was REMOVED
         * then we need to reset it
         * */
        priv->removed = FALSE;
        g_task_return_boolean (task, TRUE);
    }
    else
    {
        g_task_return_error (task, error);
    }

    g_object_unref (task);
}

static void
identity_verify_reply (GObject *object,
                       GAsyncResult *res,
                       gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    gboolean valid;
    GError *error = NULL;
    GTask *task = (GTask *)userdata;

    g_return_if_fail (task != NULL);

    if (!sso_identity_call_verify_secret_finish (proxy, &valid, res, &error)) {
        g_task_return_error (task, error);
        g_object_unref (task);
        return;
    }

    g_task_return_boolean (task, TRUE);
    g_object_unref (task);
}

static void
identity_verify_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)object;
    SignonIdentityPrivate *priv = NULL;
    GTask *task = (GTask *)user_data;

    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    g_return_if_fail (self->priv != NULL);
    priv = self->priv;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    g_return_if_fail (task != NULL);

    if (priv->removed == TRUE)
    {
        g_task_return_new_error (task,
                                 signon_error_quark (),
                                 SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                 "Already removed from database.");
        g_object_unref (task);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        g_task_return_error (task, g_error_copy (error));
        g_object_unref (task);
    }
    else
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);
        g_return_if_fail (priv->proxy != NULL);

        sso_identity_call_verify_secret (priv->proxy,
                                         g_task_get_task_data (task),
                                         g_task_get_cancellable (task),
                                         identity_verify_reply,
                                         task);
    }
}

/**
 * signon_identity_verify_secret:
 * @self: the #SignonIdentity.
 * @secret: the secret (password) to be verified.
 * @cancellable: (nullable): optional #GCancellable object, %NULL to ignore.
 * @callback: a callback which will be called when the verification is done.
 * @user_data: user data to be passed to the callback.
 *
 * Verifies the given secret.
 *
 * Since: 2.0
 */
void
signon_identity_verify_secret (SignonIdentity *self,
                               const gchar *secret,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
    GTask *task = NULL;

    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_source_tag (task, signon_identity_verify_secret);
    g_task_set_task_data (task, g_strdup (secret), (GDestroyNotify)g_free);

    signon_proxy_call_when_ready (self,
                                  identity_object_quark(),
                                  identity_verify_ready_cb,
                                  task);
}

/**
 * signon_identity_verify_secret_finish:
 * @self: the #SignonIdentity.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to
 * signon_identity_verify_secret().
 * @error: return location for error, or %NULL.
 *
 * Collect the result of the signon_identity_verify_secret() operation.
 *
 * Returns: %TRUE if the secret is valid, %FALSE otherwise.
 */
gboolean
signon_identity_verify_secret_finish (SignonIdentity *self,
                                      GAsyncResult *res,
                                      GError **error)
{
    g_return_val_if_fail (g_task_is_valid (res, self), FALSE);

    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
identity_process_updated (SignonIdentity *self)
{
    DEBUG ("%d %s", __LINE__, __func__);

    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    SignonIdentityPrivate *priv = self->priv;
    g_return_if_fail (priv->proxy != NULL);

    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;
    priv->updated = FALSE;
}

static void
identity_process_removed (SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    DEBUG ("%d %s", __LINE__, __func__);

    SignonIdentityPrivate *priv = self->priv;

    if (priv->removed == TRUE)
        return;

    priv->removed = TRUE;
    signon_identity_info_free (priv->identity_info);
    priv->identity_info = NULL;

    signon_identity_set_id (self, 0);
}

static void
identity_process_signout(SignonIdentity *self)
{
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    DEBUG ("%d %s", __LINE__, __func__);
    SignonIdentityPrivate *priv = self->priv;

    if (priv->signed_out == TRUE)
        return;

    GSList *llink = priv->sessions;
    while (llink)
    {
        GSList *next = llink->next;
        g_object_unref (G_OBJECT(llink->data));
        llink = next;
    }

    priv->signed_out = TRUE;
    g_signal_emit(G_OBJECT(self), signals[SIGNEDOUT_SIGNAL], 0);
}

static void
identity_signout_reply (GObject *object,
                        GAsyncResult *res,
                        gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    GError *error = NULL;
    GTask *task = (GTask *)userdata;
    SignonIdentity *self = NULL;
    gboolean result = TRUE;

    g_return_if_fail (task != NULL);

    self = g_task_get_source_object (task);
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    if (sso_identity_call_sign_out_finish (proxy, &result, res, &error))
    {
        // FIXME: there is an issue in signond that makes result always return FALSE
        //if (result)
            g_task_return_boolean (task, TRUE);
        /*else
            g_task_return_new_error (task,
                                     signon_error_quark (),
                                     SIGNON_ERROR_SIGNOUT_FAILED,
                                     "The Daemon could not Sign out the Identity.");*/
    }
    else
        g_task_return_error (task, error);

    g_object_unref (task);
}

static void
identity_removed_reply (GObject *object, GAsyncResult *res,
                        gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    GError *error = NULL;
    GTask *task = (GTask *)userdata;
    SignonIdentity *self = NULL;

    g_return_if_fail (task != NULL);

    self = g_task_get_source_object (task);
    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    if (sso_identity_call_remove_finish (proxy, res, &error))
        g_task_return_boolean (task, TRUE);
    else
        g_task_return_error (task, error);

    g_object_unref (task);
}

static void
identity_signout_ready_cb(gpointer object, const GError *error, gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)object;
    SignonIdentityPrivate *priv = NULL;
    GTask *task = (GTask *)user_data;

    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    g_return_if_fail (self->priv != NULL);
    priv = self->priv;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    g_return_if_fail (task != NULL);

    if (priv->removed == TRUE)
    {
        g_task_return_new_error (task,
                                 signon_error_quark (),
                                 SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                 "Already removed from database.");
        g_object_unref (task);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        g_task_return_error (task, g_error_copy (error));
        g_object_unref (task);
    }
    else
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_sign_out (priv->proxy,
                                    priv->cancellable,
                                    identity_signout_reply,
                                    task);
    }
}

static void
identity_remove_ready_cb (gpointer object,
                          const GError *error,
                          gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)object;
    SignonIdentityPrivate *priv = NULL;
    GTask *task = (GTask *)user_data;

    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    g_return_if_fail (self->priv != NULL);
    priv = self->priv;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    g_return_if_fail (task != NULL);

    if (priv->removed == TRUE)
    {
        g_task_return_new_error (task,
                                 signon_error_quark (),
                                 SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                 "Already removed from database.");
        g_object_unref (task);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        g_task_return_error (task, g_error_copy (error));
        g_object_unref (task);
    }
    else
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_remove (priv->proxy,
                                  g_task_get_cancellable (task),
                                  identity_removed_reply,
                                  task);
    }
}

/**
 * signon_identity_remove:
 * @self: the #SignonIdentity.
 * @cancellable: (nullable): optional #GCancellable object, %NULL to ignore.
 * @callback: a callback which will be called when the operation has completed.
 * @user_data: user data to be passed to the callback.
 *
 * Removes the corresponding credentials record from the database.
 *
 * Since: 2.0
 */
void
signon_identity_remove (SignonIdentity *self,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
    GTask *task = NULL;
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_source_tag (task, signon_identity_remove);

    signon_proxy_call_when_ready (self,
                                  identity_object_quark (),
                                  identity_remove_ready_cb,
                                  task);
}

gboolean
signon_identity_remove_finish (SignonIdentity *self,
                               GAsyncResult *res,
                               GError **error)
{
    g_return_val_if_fail (g_task_is_valid (res, self), FALSE);

    return g_task_propagate_boolean (G_TASK (res), error);
}

/**
 * signon_identity_sign_out:
 * @self: the #SignonIdentity.
 * @cancellable: (nullable): optional #GCancellable object, %NULL to ignore.
 * @callback: a callback which will be called when the operation has completed.
 * @user_data: user data to be passed to the callback.
 *
 * Asks signond to close all authentication sessions for this
 * identity, and to remove any stored secrets associated with it (password and
 * authentication tokens).
 *
 * Since: 2.0
 */

void
signon_identity_sign_out (SignonIdentity *self,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
    GTask *task = NULL;
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_source_tag (task, signon_identity_sign_out);

    signon_proxy_call_when_ready (self,
                                  identity_object_quark(),
                                  identity_signout_ready_cb,
                                  task);
}

gboolean
signon_identity_sign_out_finish (SignonIdentity *self,
                                 GAsyncResult *res,
                                 GError **error)
{
    g_return_val_if_fail (g_task_is_valid (res, self), FALSE);

    return g_task_propagate_boolean (G_TASK (res), error);
}

static void
identity_query_info_reply (GObject *object,
                           GAsyncResult *res,
                           gpointer userdata)
{
    SsoIdentity *proxy = SSO_IDENTITY (object);
    SignonIdentity *self = NULL;
    SignonIdentityPrivate *priv = NULL;
    GVariant *identity_data = NULL;
    GError *error = NULL;
    GTask *task = (GTask *)userdata;

    DEBUG ("%d %s", __LINE__, __func__);

    g_return_if_fail (task != NULL);

    self = g_task_get_source_object (task);

    g_return_if_fail (self != NULL);
    g_return_if_fail (self->priv != NULL);

    priv = self->priv;
    if (sso_identity_call_get_info_finish (proxy, &identity_data, res, &error))
    {
        if (priv->identity_info)
            g_clear_pointer (&priv->identity_info, (GDestroyNotify)signon_identity_info_free);

        priv->identity_info = signon_identity_info_new_from_variant (identity_data);
        g_variant_unref (identity_data);
        signon_identity_set_id (self, signon_identity_info_get_id (priv->identity_info));

        priv->updated = TRUE;
        g_task_return_pointer (task, signon_identity_info_copy (priv->identity_info), (GDestroyNotify)signon_identity_info_free);
    }
    else
    {
        g_task_return_error (task, error);
    }

    g_object_unref (task);
}

static void
identity_query_ready_cb (gpointer object, const GError *error, gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)object;
    SignonIdentityPrivate *priv = NULL;
    GTask *task = (GTask *)user_data;

    g_return_if_fail (SIGNON_IS_IDENTITY (self));
    g_return_if_fail (self->priv != NULL);
    priv = self->priv;

    DEBUG ("%s %d", G_STRFUNC, __LINE__);

    g_return_if_fail (task != NULL);

    if (priv->removed == TRUE)
    {
        DEBUG ("Already removed from database.");
        g_task_return_new_error (task,
                                 signon_error_quark (),
                                 SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                 "Already removed from database.");
        g_object_unref (task);
    }
    else if (error)
    {
        DEBUG ("IdentityError: %s", error->message);
        g_task_return_error (task, g_error_copy (error));
        g_object_unref (task);
    }
    else if (priv->id == 0)
    {
        DEBUG ("Identity is not stored and has no info yet");
        g_task_return_new_error (task,
                                 signon_error_quark (),
                                 SIGNON_ERROR_IDENTITY_NOT_FOUND,
                                 "Identity is not stored and has no info yet");
        g_object_unref (task);
    }
    else if (priv->updated == FALSE || priv->identity_info == NULL)
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        g_return_if_fail (priv->proxy != NULL);
        sso_identity_call_get_info (priv->proxy,
                                    g_task_get_cancellable (task),
                                    identity_query_info_reply,
                                    task);
    }
    else
    {
        DEBUG ("%s %d", G_STRFUNC, __LINE__);

        g_task_return_pointer (task, signon_identity_info_copy (priv->identity_info), (GDestroyNotify)signon_identity_info_free);
        g_object_unref (task);
    }
}

/**
 * signon_identity_query_info:
 * @self: the #SignonIdentity.
 * @cancellable: (nullable): optional #GCancellable object, %NULL to ignore.
 * @callback: a callback which will be called when the #SignonIdentityInfo is
 * available.
 * @user_data: user data to be passed to the callback.
 *
 * Fetches the #SignonIdentityInfo associated with this identity.
 *
 * Since: 2.0
 */
void
signon_identity_query_info (SignonIdentity *self,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
    GTask *task = NULL;
    g_return_if_fail (SIGNON_IS_IDENTITY (self));

    task = g_task_new (self, cancellable, callback, user_data);
    g_task_set_source_tag (task, signon_identity_query_info);

    signon_proxy_call_when_ready (self,
                                  identity_object_quark (),
                                  identity_query_ready_cb,
                                  task);
}

/**
 * signon_identity_query_info_finish:
 * @self: the #SignonIdentity.
 * @res: A #GAsyncResult obtained from the #GAsyncReadyCallback passed to
 * signon_identity_query_info().
 * @error: return location for error, or %NULL.
 *
 * Collect the result of the signon_identity_query_info() operation.
 *
 * Returns: the #SignonIdentityInfo associated with this identity.
 */
SignonIdentityInfo *
signon_identity_query_info_finish (SignonIdentity *self,
                                   GAsyncResult *res,
                                   GError **error)
{
    g_return_val_if_fail (g_task_is_valid (res, self), NULL);

    return g_task_propagate_pointer (G_TASK (res), error);
}
