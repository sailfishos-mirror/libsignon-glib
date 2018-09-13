/* -*- Mode: C; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This file is part of libsignon-glib
 *
 * Copyright (C) 2009-2011 Nokia Corporation.
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
 * @example check_signon.c
 * Shows how to initialize the framework.
 */

#define SIGNON_DISABLE_DEPRECATION_WARNINGS

#include "libsignon-glib/signon-internals.h"
#include "libsignon-glib/signon-auth-service.h"
#include "libsignon-glib/signon-auth-session.h"
#include "libsignon-glib/signon-identity.h"
#include "libsignon-glib/signon-errors.h"

#include <glib.h>
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static GMainLoop *main_loop = NULL;
static SignonIdentity *identity = NULL;
static SignonAuthService *auth_service = NULL;

#define SIGNOND_IDLE_TIMEOUT (5 + 2)

static gboolean _contains(gchar **list, gchar *item)
{
    gboolean present = FALSE;
    gint i = 0;
    while (list[i] != NULL)
    {
        if (g_strcmp0 (item, list[i]) == 0) present = TRUE;
        i++;
    }
    return present;
}

static void
end_test ()
{
    if (auth_service)
    {
        g_object_unref (auth_service);
        auth_service = NULL;
    }

    if (identity)
    {
        g_object_unref (identity);
        identity = NULL;
    }

    if (main_loop)
    {
        g_main_loop_quit (main_loop);
        g_main_loop_unref (main_loop);
        main_loop = NULL;
    }
}

static gboolean
quit_loop (gpointer user_data)
{
    GMainLoop *loop = user_data;
    g_main_loop_quit (loop);
    return FALSE;
}

static void
run_main_loop_for_n_seconds(guint seconds)
{
    GMainLoop *loop = g_main_loop_new (NULL, FALSE);
    g_timeout_add_seconds (seconds, quit_loop, loop);
    g_main_loop_run (loop);
    g_main_loop_unref (loop);
}

START_TEST(test_init)
{
    g_debug("%s", G_STRFUNC);
    auth_service = signon_auth_service_new ();
    main_loop = g_main_loop_new (NULL, FALSE);

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");
    end_test ();
}
END_TEST

static void
signon_query_methods_cb (GObject *source_object,
                         GAsyncResult *res,
                         gpointer user_data)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (source_object);
    GError *error = NULL;
    gchar **methods = signon_auth_service_get_methods_finish (auth_service, res, &error);
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_error_free (error);
        g_main_loop_quit (main_loop);
        fail();
    }

    gboolean has_ssotest = FALSE;

    fail_unless (g_strcmp0 (user_data, "Hello") == 0, "Got wrong string");
    fail_unless (methods != NULL, "The methods does not exist");

    for (gint i = 0; methods[i] != NULL; i++)
    {
        const gchar *method = methods[i];
        if (g_strcmp0 (method, "ssotest") == 0)
        {
            has_ssotest = TRUE;
            break;
        }
    }
    fail_unless (has_ssotest, "ssotest method does not exist");

    g_main_loop_quit (main_loop);
}

START_TEST(test_query_methods)
{
    g_debug("%s", G_STRFUNC);
    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);

    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    signon_auth_service_get_methods (auth_service, NULL, signon_query_methods_cb, "Hello");
    g_main_loop_run (main_loop);
    end_test ();
}
END_TEST

START_TEST(test_query_methods_sync)
{
    gchar **methods = NULL;
    GError *error = NULL;

    g_debug("%s", G_STRFUNC);

    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    methods = signon_auth_service_get_methods_sync (auth_service, NULL, &error);
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_error_free (error);
        fail();
    }

    gboolean has_ssotest = FALSE;

    fail_unless (methods != NULL, "The methods does not exist");

    for (gint i = 0; methods[i] != NULL; i++)
    {
        const gchar *method = methods[i];
        if (g_strcmp0 (method, "ssotest") == 0)
        {
            has_ssotest = TRUE;
            break;
        }
    }
    fail_unless (has_ssotest, "ssotest method does not exist");
}
END_TEST

static void
signon_query_mechanisms_cb (GObject *source_object,
                            GAsyncResult *res,
                            gpointer user_data)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (source_object);
    GError *error = NULL;
    gchar **mechanisms = signon_auth_service_get_mechanisms_finish (auth_service, res, &error);
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_error_free (error);
        g_main_loop_quit (main_loop);
        fail();
    }

    gboolean has_mech1 = FALSE;
    gboolean has_mech2 = FALSE;
    gboolean has_mech3 = FALSE;

    fail_unless (strcmp (user_data, "Hello") == 0, "Got wrong string");
    fail_unless (mechanisms != NULL, "The mechanisms does not exist");

    for (gint i = 0; mechanisms[i] != NULL; i++)
    {
        const gchar *mechanism = mechanisms[i];
        if (g_strcmp0 (mechanism, "mech1") == 0)
            has_mech1 = TRUE;

        if (g_strcmp0 (mechanism, "mech2") == 0)
            has_mech2 = TRUE;

        if (g_strcmp0 (mechanism, "mech3") == 0)
            has_mech3 = TRUE;
    }

    fail_unless (has_mech1, "mech1 mechanism does not exist");
    fail_unless (has_mech2, "mech2 mechanism does not exist");
    fail_unless (has_mech3, "mech3 mechanism does not exist");

    g_main_loop_quit (main_loop);
}

static void
signon_query_mechanisms_cb_fail (GObject *source_object,
                                 GAsyncResult *res,
                                  gpointer user_data)
{
    SignonAuthService *auth_service = SIGNON_AUTH_SERVICE (source_object);
    GError *error = NULL;
    gchar **mechanisms = signon_auth_service_get_mechanisms_finish (auth_service, res, &error);
    fail_unless (error != NULL);
    fail_unless (mechanisms == NULL);
    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_METHOD_NOT_KNOWN);
    g_main_loop_quit (main_loop);
}

START_TEST(test_query_mechanisms)
{
    g_debug("%s", G_STRFUNC);
    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    signon_auth_service_get_mechanisms (auth_service,
                                        "ssotest",
                                        NULL,
                                        signon_query_mechanisms_cb,
                                        "Hello");
    if(!main_loop)
        main_loop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (main_loop);

    /* Test a non existing method */
    signon_auth_service_get_mechanisms (auth_service,
                                        "non-existing",
                                        NULL,
                                        signon_query_mechanisms_cb_fail,
                                        "Hello");
    g_main_loop_run (main_loop);
    end_test ();
}
END_TEST

START_TEST(test_query_mechanisms_sync)
{
    gchar **mechanisms = NULL;
    GError *error = NULL;

    g_debug("%s", G_STRFUNC);

    auth_service = signon_auth_service_new ();

    fail_unless (SIGNON_IS_AUTH_SERVICE (auth_service),
                 "Failed to initialize the AuthService.");

    mechanisms = signon_auth_service_get_mechanisms_sync (auth_service, "ssotest", NULL, &error);
    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_error_free (error);
        fail();
    }

    gboolean has_mech1 = FALSE;
    gboolean has_mech2 = FALSE;
    gboolean has_mech3 = FALSE;

    fail_unless (mechanisms != NULL, "The mechanisms does not exist");

    for (gint i = 0; mechanisms[i] != NULL; i++)
    {
        const gchar *mechanism = mechanisms[i];
        if (g_strcmp0 (mechanism, "mech1") == 0)
            has_mech1 = TRUE;

        if (g_strcmp0 (mechanism, "mech2") == 0)
            has_mech2 = TRUE;

        if (g_strcmp0 (mechanism, "mech3") == 0)
            has_mech3 = TRUE;
    }

    fail_unless (has_mech1, "mech1 mechanism does not exist");
    fail_unless (has_mech2, "mech2 mechanism does not exist");
    fail_unless (has_mech3, "mech3 mechanism does not exist");

    /* Test a non existing method */
    mechanisms = signon_auth_service_get_mechanisms_sync (auth_service, "non-existing", NULL, &error);
    fail_unless (error != NULL);
    fail_unless (mechanisms == NULL);
    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_METHOD_NOT_KNOWN);
}
END_TEST

static void
test_auth_session_process2_async_cb (GObject *source_object,
                                     GAsyncResult *res,
                                     gpointer user_data)
{
    SignonAuthSession *self = (SignonAuthSession *)source_object;
    GError *error = NULL;
    GVariant *reply = signon_auth_session_process_finish (self, res, &error);
    gboolean ok;

    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_error_free (error);
        g_main_loop_quit (main_loop);
        fail();
    }

    fail_unless (reply != NULL, "Could not process the auth session");

    gchar* username2 = NULL;

    ok = g_variant_lookup (reply, SIGNON_SESSION_DATA_USERNAME, "&s", &username2);
    ck_assert (ok);
    ck_assert_str_eq (username2, "test_username");

    g_variant_unref (reply);

    g_main_loop_quit (main_loop);
}

static void
test_auth_session_states_cb (SignonAuthSession *self,
                             gint state,
                             gchar *message,
                             gpointer user_data)
{
    gint *state_counter = (gint *)user_data;
    (*state_counter)++;
}

START_TEST(test_auth_session_creation)
{
    GError *err = NULL;
    gpointer auth_session_sentinel;
    gpointer idty_sentinel;
    const gchar *method = NULL;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new(NULL, NULL);
    fail_unless (idty != NULL, "Cannot create Identity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                    "ssotest",
                                                                    &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    method = signon_auth_session_get_method (auth_session);

    fail_unless (g_strcmp0 (method, "ssotest") == 0, "Wrong AuthSession method name");

    g_object_add_weak_pointer (G_OBJECT (idty), &idty_sentinel);
    g_object_add_weak_pointer (G_OBJECT (auth_session), &auth_session_sentinel);

    g_object_unref (idty);
    fail_unless (SIGNON_IS_IDENTITY(idty), "Identity must stay untill all its session are not destroyed");
    g_object_unref (auth_session);

    fail_if (auth_session_sentinel != NULL, "AuthSession is not synchronized with parent Identity");
    fail_if (idty_sentinel != NULL, "Identity is not synchronized with its AuthSession");

    g_clear_error(&err);
}
END_TEST

static void
test_auth_session_process_async_cb (GObject *source_object,
                                    GAsyncResult *res,
                                    gpointer user_data)
{
    SignonAuthSession *auth_session = SIGNON_AUTH_SESSION (source_object);
    GVariant **v_reply = user_data;
    GError *error = NULL;

    fail_unless (SIGNON_IS_AUTH_SESSION (source_object));

    *v_reply = signon_auth_session_process_finish (auth_session, res, &error);
    fail_unless (error == NULL);

    g_main_loop_quit (main_loop);
}

START_TEST(test_auth_session_process_async)
{
    gint state_counter = 0;
    GError *err = NULL;
    GVariantBuilder builder;
    GVariant *session_data, *reply;
    gchar *username, *realm;
    gboolean ok;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new(NULL, NULL);
    fail_unless (idty != NULL, "Cannot create Identity object");

    SignonAuthSession *auth_session = signon_identity_create_session(idty,
                                                                     "ssotest",
                                                                     &err);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");

    g_clear_error(&err);

    g_signal_connect(auth_session, "state-changed",
                     G_CALLBACK(test_auth_session_states_cb), &state_counter);

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           SIGNON_SESSION_DATA_USERNAME,
                           g_variant_new_string ("test_username"));
    g_variant_builder_add (&builder, "{sv}",
                           SIGNON_SESSION_DATA_SECRET,
                           g_variant_new_string ("test_pw"));

    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_auth_session_process_async_cb,
                                 &reply);
    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);
    fail_unless (state_counter == 12, "Wrong numer of state change signals: %d", state_counter);

    fail_unless (reply != NULL);
    session_data = NULL;

    ok = g_variant_lookup (reply, SIGNON_SESSION_DATA_USERNAME, "&s", &username);
    ck_assert (ok);
    ck_assert_str_eq (username, "test_username");
    ok = g_variant_lookup (reply, SIGNON_SESSION_DATA_REALM, "&s", &realm);
    ck_assert (ok);
    ck_assert_str_eq (realm, "testRealm_after_test");

    g_variant_unref (reply);

    g_object_unref (auth_session);
    g_object_unref (idty);

    end_test ();
}
END_TEST

static void
test_auth_session_process_failure_cb (GObject *source_object,
                                      GAsyncResult *res,
                                      gpointer user_data)
{
    SignonAuthSession *auth_session = SIGNON_AUTH_SESSION (source_object);
    GVariant *v_reply;
    GError **error = user_data;

    fail_unless (SIGNON_IS_AUTH_SESSION (source_object));

    v_reply = signon_auth_session_process_finish (auth_session, res, error);
    fail_unless (v_reply == NULL);

    g_main_loop_quit (main_loop);
}

START_TEST(test_auth_session_process_failure)
{
    SignonAuthSession *auth_session;
    GVariantBuilder builder;
    GVariant *session_data;
    GError *error = NULL;

    g_debug("%s", G_STRFUNC);

    auth_session = signon_auth_session_new (0, "nonexisting-method", &error);
    fail_unless (auth_session != NULL, "Cannot create AuthSession object");
    fail_unless (error == NULL);

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           "key", g_variant_new_string ("value"));

    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_auth_session_process_failure_cb,
                                 &error);

    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);
    fail_unless (error != NULL);
    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_METHOD_NOT_KNOWN);

    g_error_free (error);
    g_object_unref (auth_session);

    end_test ();
}
END_TEST

START_TEST(test_auth_session_process_cancel)
{
    SignonAuthSession *auth_session;
    GVariantBuilder builder;
    GVariant *session_data;
    GError *error = NULL;

    g_debug("%s", G_STRFUNC);

    auth_session = signon_auth_session_new (0, "nonexisting-method", &error);
    fail_unless (auth_session != NULL, "Cannot create AuthSession object");
    fail_unless (error == NULL);

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           "key", g_variant_new_string ("value"));

    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_auth_session_process_failure_cb,
                                 &error);
    signon_auth_session_cancel (auth_session);

    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);
    fail_unless (error != NULL);
    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_METHOD_NOT_KNOWN);

    g_error_free (error);
    g_object_unref (auth_session);

    end_test ();
}
END_TEST

static void
test_auth_session_process_after_store_cb (GObject *source_object,
                                          GAsyncResult *res,
                                          gpointer user_data)
{
    gchar *v_username;
    GError *error = NULL;
    GVariantDict *dict = NULL;
    GVariant *reply = signon_auth_session_process_finish ((SignonAuthSession *)source_object, res, &error);

    if (error != NULL)
    {
        fail("Got error: %s", error->message);
        g_main_loop_quit (main_loop);
        return;
    }

    fail_unless (reply != NULL, "The result is empty");

    dict = g_variant_dict_new (reply);
    g_variant_dict_lookup (dict, SIGNON_SESSION_DATA_USERNAME, "s", &v_username);
    fail_unless (g_strcmp0 (v_username, "Nice user") == 0,
                 "Wrong value of username");
    g_variant_dict_unref (dict);
    g_free (v_username);

    g_main_loop_quit (main_loop);
}

static void
test_auth_session_process_after_store_start_session (GObject *source_object,
                                                     GAsyncResult *res,
                                                     gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;
    GVariant *session_data = NULL;
    guint32 id;
    SignonAuthSession *auth_session = (SignonAuthSession *)user_data;

    fail_unless (auth_session != NULL);
    fail_unless (SIGNON_IS_AUTH_SESSION (auth_session));

    if (!signon_identity_store_info_finish (self, res, &error)) {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
        g_main_loop_quit (main_loop);
        return;
    }

    id = signon_identity_get_id (self);
    fail_unless (id > 0);

    session_data = g_variant_new (g_variant_type_peek_string (G_VARIANT_TYPE_VARDICT), NULL);

    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_auth_session_process_after_store_cb,
                                 NULL);
}

START_TEST(test_auth_session_process_after_store)
{
    SignonIdentityInfo *info = NULL;
    SignonIdentity *identity = NULL;
    GList *acl = g_list_append (NULL, signon_security_context_new_from_values ("*", "*"));
    SignonAuthSession *auth_session = NULL;
    GError *error = NULL;

    g_debug("%s", G_STRFUNC);

    main_loop = g_main_loop_new (NULL, FALSE);

    identity = signon_identity_new ();
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "Nice user");
    signon_identity_info_set_access_control_list (info, acl);

    g_list_free_full (acl, (GDestroyNotify)signon_security_context_free);

    /*
     * This auth session will get an updated Identity ID when the identity
     * get created.
     */
    auth_session = signon_identity_create_session(identity,
                                                  "ssotest",
                                                  &error);

    fail_unless (auth_session != NULL, "Cannot create AuthSession object");
    if (error != NULL)
    {
        fail ("Got error: %s", error->message);
        g_clear_error (&error);
    }

    signon_identity_store_info (identity,
                                info,
                                NULL,
                                test_auth_session_process_after_store_start_session,
                                auth_session);

    g_main_loop_run (main_loop);

    g_object_unref (identity);
    g_object_unref (auth_session);
    signon_identity_info_free (info);

    end_test ();
}
END_TEST

static void add_methods_to_identity_info (SignonIdentityInfo *info)
{
    const gchar *mechanisms[] = {
            "mechanism1",
            "mechanism2",
            "mechanism3",
            NULL
    };

    signon_identity_info_set_method (info, "method1", mechanisms);
    signon_identity_info_set_method (info, "method2", mechanisms);
    signon_identity_info_set_method (info, "method3", mechanisms);
}

static void new_identity_store_credentials_cb (GObject *source_object,
                                               GAsyncResult *res,
                                               gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;
    gint *new_id = user_data;
    guint32 id;

    if (!signon_identity_store_info_finish (self, res, &error)) {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
    }

    id = signon_identity_get_id (self);
    fail_unless (id > 0);

    *new_id = id;

    g_object_unref (self);
    g_main_loop_quit (main_loop);
}

static guint
new_identity()
{
    SignonIdentity *identity;
    GList *acl = g_list_append (NULL, signon_security_context_new_from_values ("*", "*"));
    guint id = 0;

    identity = signon_identity_new(NULL, NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity));

    SignonIdentityInfo *info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "caption");

    signon_identity_info_set_access_control_list (info, acl);
    g_list_free_full (acl, (GDestroyNotify)signon_security_context_free);

    signon_identity_store_info (identity,
                                info,
                                NULL,
                                new_identity_store_credentials_cb,
                                &id);
    signon_identity_info_free (info);

    if (id == 0)
        g_main_loop_run (main_loop);

    return id;

}

static gboolean
identity_registered_cb (gpointer data)
{
    g_main_loop_quit (main_loop);
    return FALSE;
}

START_TEST(test_get_existing_identity)
{
    g_debug("%s", G_STRFUNC);

    main_loop = g_main_loop_new (NULL, FALSE);
    guint id = new_identity();

    fail_unless (id != 0);

    identity = signon_identity_new_from_db(id);

    fail_unless (identity != NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    g_timeout_add (1000, identity_registered_cb, identity);
    g_main_loop_run (main_loop);

    end_test ();
}
END_TEST

START_TEST(test_get_nonexisting_identity)
{
    g_debug("%s", G_STRFUNC);
    identity = signon_identity_new_from_db(G_MAXINT);

    fail_unless (identity != NULL);
    fail_unless (SIGNON_IS_IDENTITY (identity),
                 "Failed to initialize the Identity.");

    g_timeout_add (1000, identity_registered_cb, identity);
    main_loop = g_main_loop_new (NULL, FALSE);
    g_main_loop_run (main_loop);

    const GError *error = NULL;
    error = signon_identity_get_last_error(identity);
    fail_unless (error != NULL);

    fail_unless (error->domain == SIGNON_ERROR);
    fail_unless (error->code == SIGNON_ERROR_IDENTITY_NOT_FOUND ||
                 error->code == SIGNON_ERROR_PERMISSION_DENIED);

    end_test ();
}
END_TEST

static void store_credentials_identity_cb (GObject *source_object,
                                           GAsyncResult *res,
                                           gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;
    guint32 id;

    if (!signon_identity_store_info_finish (self, res, &error)) {
        g_warning ("%s %d: %s", G_STRFUNC, __LINE__, error->message);
        fail();
    }

    id = signon_identity_get_id (self);
    fail_unless (id > 0);

    if (user_data != NULL)
    {
        gint *last_id = (gint *)user_data;
        g_warning ("%s (prev_id vs new_id): %d vs %d", G_STRFUNC, *last_id, id);

        fail_unless (id == (*last_id) + 1);
        (*last_id) += 1;
    }

    /* Wait some time to ensure that the info-updated signals are
     * processed
     */
    g_timeout_add_seconds (2, quit_loop, main_loop);
}

START_TEST(test_store_credentials_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new(NULL, NULL);
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    main_loop = g_main_loop_new (NULL, FALSE);
    gint last_id = new_identity();

    SignonIdentityInfo *info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "caption");
    add_methods_to_identity_info (info);

    signon_identity_store_info (idty,
                                info,
                                NULL,
                                store_credentials_identity_cb,
                                &last_id);
    signon_identity_info_free (info);

    g_main_loop_run (main_loop);

    g_object_unref(idty);
    end_test ();
}
END_TEST

static void identity_verify_secret_cb (GObject *source_object,
                                       GAsyncResult *res,
                                       gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;
    gboolean valid = signon_identity_verify_secret_finish (self, res, &error);

    fail_unless (error == NULL, "The callback returned error for proper secret");
    fail_unless (valid == TRUE, "The callback gives FALSE for proper secret");

    g_main_loop_quit((GMainLoop *)user_data);
}

START_TEST(test_verify_secret_identity)
{
    GList *acl = g_list_append (NULL, signon_security_context_new_from_values ("*", "*"));

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new(NULL, NULL);
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    gchar secret[] = "007";
    main_loop = g_main_loop_new (NULL, FALSE);

    SignonIdentityInfo *info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, secret, TRUE);
    signon_identity_info_set_caption (info, "caption");

    signon_identity_info_set_access_control_list (info, acl);
    add_methods_to_identity_info (info);
    g_list_free_full (acl, (GDestroyNotify)signon_security_context_free);

    signon_identity_store_info (idty,
                                info,
                                NULL,
                                store_credentials_identity_cb,
                                NULL);
    signon_identity_info_free (info);
    g_main_loop_run (main_loop);

    signon_identity_verify_secret (idty,
                                   secret,
                                   NULL,
                                   identity_verify_secret_cb,
                                   main_loop);

    g_main_loop_run (main_loop);

    g_object_unref (idty);
    end_test ();
}
END_TEST

static void identity_remove_cb (GObject *source_object,
                                GAsyncResult *res,
                                gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;

    g_warning (" %s ", __func__);
    if (signon_identity_remove_finish (self, res, &error)) {
        g_warning ("No error");
        fail_if (user_data != NULL, "The callback must return an error");
    }
    else
    {
        g_warning ("Error: %s ", error->message);
        g_error_free (error);
        fail_if (user_data == NULL, "There should be no error in callback");
    }

    g_main_loop_quit(main_loop);
}

START_TEST(test_remove_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    main_loop = g_main_loop_new (NULL, FALSE);
    /*
     * Try to remove non-stored idetnity
     * */
    signon_identity_remove(idty, NULL, identity_remove_cb, NULL);
    g_main_loop_run (main_loop);

    /*
     * Try to remove existing identy
     * */

    gint id = new_identity();
    SignonIdentity *idty2 = signon_identity_new_from_db (id);

    signon_identity_remove(idty2, NULL, identity_remove_cb, NULL);
    g_main_loop_run (main_loop);

    /*
     * Try to remove already removed
     * */

    signon_identity_remove(idty2, NULL, identity_remove_cb, GINT_TO_POINTER(TRUE));

    g_object_unref (idty);
    g_object_unref (idty2);
    end_test ();
}
END_TEST

static void identity_info_cb (GObject *source_object,
                              GAsyncResult *res,
                              gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;
    SignonIdentityInfo *info = signon_identity_query_info_finish (self, res, &error);

    if (error)
    {
        g_warning ("%s: Error: %s ", __func__, error->message);
        fail_if (info != NULL, "Error: %s ", error->message);
        g_main_loop_quit(main_loop);
        return;
    }

    g_warning ("No error");

    SignonIdentityInfo **pattern_ptr = (SignonIdentityInfo **)user_data;
    SignonIdentityInfo *pattern = NULL;

     if (pattern_ptr)
         pattern = (*pattern_ptr);

     if (pattern == NULL)
         fail_unless (info == NULL, "The info must be NULL");
     else
     {
         fail_unless (info != NULL, "The info must be non-null");
         fail_unless (g_strcmp0 (signon_identity_info_get_username(info),
                                 signon_identity_info_get_username(pattern)) == 0, "The info has wrong username");
         fail_unless (g_strcmp0 (signon_identity_info_get_caption(info),
                                 signon_identity_info_get_caption(pattern)) == 0, "The info has wrong caption");

         GHashTable *methods = (GHashTable *)signon_identity_info_get_methods (info);
         gchar **mechs1 = g_hash_table_lookup (methods, "method1");
         gchar **mechs2 = g_hash_table_lookup (methods, "method2");
         gchar **mechs3 = g_hash_table_lookup (methods, "method3");

         fail_unless (g_strv_length (mechs1) == 3);
         fail_unless (g_strv_length (mechs2) == 3);
         fail_unless (g_strv_length (mechs3) == 3);

         fail_unless (_contains(mechs1, "mechanism1"));
         fail_unless (_contains(mechs1, "mechanism2"));
         fail_unless (_contains(mechs1, "mechanism3"));

         fail_unless (_contains(mechs2, "mechanism1"));
         fail_unless (_contains(mechs2, "mechanism2"));
         fail_unless (_contains(mechs2, "mechanism3"));

         fail_unless (_contains(mechs3, "mechanism1"));
         fail_unless (_contains(mechs3, "mechanism2"));
         fail_unless (_contains(mechs3, "mechanism3"));
     }

     if (info && pattern_ptr)
     {
         signon_identity_info_free (pattern);
         *pattern_ptr = signon_identity_info_copy (info);
     }

     g_main_loop_quit(main_loop);
}

static SignonIdentityInfo *create_standard_info()
{
    GList *acl = g_list_append (NULL, signon_security_context_new_from_values ("*", "*"));
    g_debug("%s", G_STRFUNC);
    SignonIdentityInfo *info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "caption");

    gchar *mechanisms[] = {
            "mechanism1",
            "mechanism2",
            "mechanism3",
            NULL
    };

    signon_identity_info_set_method (info, "method1", (const gchar **)mechanisms);
    signon_identity_info_set_method (info, "method2", (const gchar **)mechanisms);
    signon_identity_info_set_method (info, "method3", (const gchar **)mechanisms);

    signon_identity_info_set_access_control_list (info, acl);
    g_list_free_full (acl, (GDestroyNotify)signon_security_context_free);

    return info;
}

START_TEST(test_info_identity)
{
    GList *acl = g_list_append (NULL, signon_security_context_new_from_values ("*", "*"));
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    SignonIdentityInfo *info = NULL;

    main_loop = g_main_loop_new (NULL, FALSE);
    /*
     * Try to get_info for non-stored idetnity
     * */
    signon_identity_query_info (idty, NULL, identity_info_cb, &info);
    g_main_loop_run (main_loop);

    info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "caption");

    signon_identity_info_set_access_control_list (info, acl);
    add_methods_to_identity_info (info);
    g_list_free_full (acl, (GDestroyNotify)signon_security_context_free);

    signon_identity_store_info (idty,
                                info,
                                NULL,
                                store_credentials_identity_cb,
                                NULL);
    signon_identity_info_free (info);

    g_main_loop_run (main_loop);

    info = signon_identity_info_new ();
    signon_identity_info_set_username (info, "James Bond");
    signon_identity_info_set_secret (info, "007", TRUE);
    signon_identity_info_set_caption (info, "caption");
    add_methods_to_identity_info (info);

    signon_identity_query_info (idty, NULL, identity_info_cb, &info);
    g_main_loop_run (main_loop);

    gint id = signon_identity_info_get_id (info);
    fail_unless (id != 0);
    SignonIdentity *idty2 = signon_identity_new_from_db (id);

    signon_identity_query_info (idty2, NULL, identity_info_cb, &info);
    g_main_loop_run (main_loop);

    /*
     * Try to update one identity and
     * have a look what will happen
     * */
    signon_identity_info_set_username (info, "James Bond_2nd version");
    signon_identity_info_set_caption (info, "caption_2nd version");

    signon_identity_store_info (idty2,
                                info,
                                NULL,
                                store_credentials_identity_cb,
                                NULL);
    g_main_loop_run (main_loop);

    signon_identity_query_info (idty, NULL, identity_info_cb, &info);
    g_main_loop_run (main_loop);
    /*
     * Try to remove existing identity and
     * have a look what will happen
     * */
    signon_identity_remove(idty2, NULL, identity_remove_cb, NULL);
    g_main_loop_run (main_loop);

    signon_identity_query_info (idty2, NULL, identity_info_cb, NULL);
    g_main_loop_run (main_loop);
    signon_identity_query_info (idty, NULL, identity_info_cb, NULL);
    g_main_loop_run (main_loop);

    signon_identity_info_free (info);
    g_object_unref (idty);
    g_object_unref (idty2);
    end_test ();
}
END_TEST

static void identity_signout_cb (GObject *source_object,
                                 GAsyncResult *res,
                                 gpointer user_data)
{
    SignonIdentity *self = (SignonIdentity *)source_object;
    GError *error = NULL;
    if (signon_identity_sign_out_finish (self, res, &error))
        g_warning ("%s: No error", G_STRFUNC);
    else
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        fail_unless (error == NULL, "There should be no error in callback");
        g_error_free (error);
    }

    g_main_loop_quit (main_loop);
}

static void identity_signout_signal_cb (gpointer instance, gpointer user_data)
{
    gint *incr = (gint *)user_data;
    (*incr) = (*incr) + 1;
    g_warning ("%s: %d", G_STRFUNC, *incr);
}

START_TEST(test_signout_identity)
{
    gpointer as1_sentinel, as2_sentinel;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    SignonIdentityInfo *info = create_standard_info();
    main_loop = g_main_loop_new (NULL, FALSE);

    signon_identity_store_info (idty,
                                info,
                                NULL,
                                store_credentials_identity_cb,
                                NULL);
    g_main_loop_run (main_loop);
    signon_identity_query_info (idty, NULL, identity_info_cb, &info);
    g_main_loop_run (main_loop);

    gint id = signon_identity_info_get_id (info);
    SignonIdentity *idty2 = signon_identity_new_from_db (id);

    /* wait some more time to ensure that the object gets registered */
    run_main_loop_for_n_seconds(2);

    signon_identity_info_free (info);

    GError *err = NULL;

    SignonAuthSession *as1 = signon_identity_create_session (idty,
                                                            "ssotest",
                                                            &err);
    fail_unless (as1 != NULL, "cannot create AuthSession");

    SignonAuthSession *as2 = signon_identity_create_session (idty2,
                                                             "ssotest",
                                                             &err);
    fail_unless (as2 != NULL, "cannot create AuthSession");

    gint counter = 0;

    g_signal_connect (idty, "signed-out",
                      G_CALLBACK(identity_signout_signal_cb), &counter);
    g_signal_connect (idty2, "signed-out",
                      G_CALLBACK(identity_signout_signal_cb), &counter);
    g_object_add_weak_pointer (G_OBJECT (as1), &as1_sentinel);
    g_object_add_weak_pointer (G_OBJECT (as2), &as2_sentinel);

    signon_identity_sign_out (idty, NULL, identity_signout_cb, NULL);
    g_main_loop_run (main_loop);

    fail_unless (counter == 2, "Lost some of SIGNOUT signals");
    fail_if (as1_sentinel != NULL, "Authsession1 was not destroyed after signout");
    fail_if (as2_sentinel != NULL, "Authsession2 was not destroyed after signout");

    g_object_unref (idty);
    g_object_unref (idty2);

    end_test ();
}
END_TEST

START_TEST(test_unregistered_identity)
{
    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    SignonIdentityInfo *info = create_standard_info();
    main_loop = g_main_loop_new (NULL, FALSE);

    signon_identity_store_info (idty,
                                info,
                                NULL,
                                store_credentials_identity_cb,
                                NULL);
    g_main_loop_run (main_loop);

    /*
     * give the time for identity to became idle
     * */
    sleep(SIGNOND_IDLE_TIMEOUT);
    SignonIdentity *idty2 = signon_identity_new();

    /*
     * give time to handle unregistered signal
     * */
    //run_main_loop_for_n_seconds(5);

    signon_identity_query_info (idty, NULL, identity_info_cb, &info);
    g_main_loop_run (main_loop);

    signon_identity_info_free (info);
    g_object_unref (idty);
    g_object_unref (idty2);

    end_test ();
}
END_TEST

START_TEST(test_unregistered_auth_session)
{
    GVariantBuilder builder;
    GVariant *session_data;
    GVariant *reply = NULL;
    gchar *username;
    gboolean ok;

    g_debug("%s", G_STRFUNC);
    SignonIdentity *idty = signon_identity_new();
    fail_unless (idty != NULL);
    fail_unless (SIGNON_IS_IDENTITY (idty),
                 "Failed to initialize the Identity.");

    main_loop = g_main_loop_new (NULL, FALSE);

    GError *err = NULL;
    SignonAuthSession *as = signon_identity_create_session(idty,
                                                          "ssotest",
                                                           &err);
    /* give time to register the objects */
    run_main_loop_for_n_seconds(2);

    /*
     * give the time for identity to became idle
     * */
    sleep(SIGNOND_IDLE_TIMEOUT);
    SignonIdentity *idty2 = signon_identity_new();

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           SIGNON_SESSION_DATA_USERNAME,
                           g_variant_new_string ("test_username"));
    g_variant_builder_add (&builder, "{sv}",
                           SIGNON_SESSION_DATA_SECRET,
                           g_variant_new_string ("test_pw"));

    session_data = g_variant_ref_sink (g_variant_builder_end (&builder));

    signon_auth_session_process (as,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_auth_session_process_async_cb,
                                 &reply);
    g_main_loop_run (main_loop);

    fail_unless (reply != NULL);

    ok = g_variant_lookup (reply, SIGNON_SESSION_DATA_USERNAME, "&s", &username);
    ck_assert (ok);
    ck_assert_str_eq (username, "test_username");

    g_variant_unref (reply);

    gchar* patterns[4];
    patterns[0] = g_strdup("mech1");
    patterns[1] = g_strdup("mech2");
    patterns[2] = g_strdup("mech3");
    patterns[3] = NULL;

    signon_auth_session_process (as,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_auth_session_process2_async_cb,
                                 NULL);
    g_main_loop_run (main_loop);

    g_object_unref (as);
    g_object_unref (idty);
    g_object_unref (idty2);

    g_free (patterns[0]);
    g_free (patterns[1]);
    g_free (patterns[2]);
    g_free (patterns[3]);

    end_test ();
}
END_TEST

static void
test_regression_unref_process_cb (GObject *source_object,
                                  GAsyncResult *res,
                                  gpointer user_data)
{
    GError *error = NULL;
    GVariant *reply = signon_auth_session_process_finish ((SignonAuthSession *)source_object, res, &error);
    gchar *v_string = NULL;

    if (error)
    {
        g_warning ("%s: %s", G_STRFUNC, error->message);
        g_main_loop_quit (main_loop);
        fail();
    }

    fail_unless (reply != NULL, "The result is empty");

    fail_unless (g_strcmp0 (user_data, "Hi there!") == 0,
                 "Didn't get expected user_data");

    g_variant_lookup (reply, "James", "&s", &v_string);
    fail_unless (v_string != NULL);
    fail_unless (g_strcmp0 (v_string, "Bond") == 0, "Wrong reply data");

    /* The next line is actually the regression we want to test */
    g_object_unref (source_object);

    g_main_loop_quit (main_loop);
}

START_TEST(test_regression_unref)
{
    SignonAuthSession *auth_session;
    GVariant *session_data;
    GError *error = NULL;
    GVariantBuilder builder;

    g_debug ("%s", G_STRFUNC);

    main_loop = g_main_loop_new (NULL, FALSE);

    auth_session = signon_auth_session_new (0, "ssotest", &error);
    fail_unless (auth_session != NULL);

    g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
    g_variant_builder_add (&builder, "{sv}",
                           "James",
                           g_variant_new_string ("Bond"));

    session_data = g_variant_builder_end (&builder);

    signon_auth_session_process (auth_session,
                                 session_data,
                                 "mech1",
                                 NULL,
                                 test_regression_unref_process_cb,
                                 "Hi there!");
    g_main_loop_run (main_loop);

    end_test ();
}
END_TEST

Suite *
signon_suite(void)
{
    Suite *s = suite_create ("signon-glib");

    /* Core test case */
    TCase * tc_core = tcase_create("Core");

    /*
     * 18 minutes timeout
     * */
    tcase_set_timeout(tc_core, 1080);
    tcase_add_test (tc_core, test_init);
    tcase_add_test (tc_core, test_query_methods);
    tcase_add_test (tc_core, test_query_methods_sync);
    tcase_add_test (tc_core, test_query_mechanisms);
    tcase_add_test (tc_core, test_query_mechanisms_sync);
    tcase_add_test (tc_core, test_get_existing_identity);
    tcase_add_test (tc_core, test_get_nonexisting_identity);

    tcase_add_test (tc_core, test_auth_session_creation);
    tcase_add_test (tc_core, test_auth_session_process_async);
    tcase_add_test (tc_core, test_auth_session_process_failure);
    tcase_add_test (tc_core, test_auth_session_process_cancel);
    tcase_add_test (tc_core, test_auth_session_process_after_store);
    tcase_add_test (tc_core, test_store_credentials_identity);
    tcase_add_test (tc_core, test_verify_secret_identity);
    tcase_add_test (tc_core, test_remove_identity);
    tcase_add_test (tc_core, test_info_identity);

    tcase_add_test (tc_core, test_signout_identity);
    tcase_add_test (tc_core, test_unregistered_identity);
    tcase_add_test (tc_core, test_unregistered_auth_session);

    tcase_add_test (tc_core, test_regression_unref);

    suite_add_tcase (s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite * s = signon_suite();
    SRunner * sr = srunner_create(s);

    srunner_set_xml(sr, "/tmp/result.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vim: set ai et tw=75 ts=4 sw=4: */

