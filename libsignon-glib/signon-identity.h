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

#ifndef _SIGNON_IDENTITY_H_
#define _SIGNON_IDENTITY_H_

#include <libsignon-glib/signon-auth-session.h>
#include <libsignon-glib/signon-identity-info.h>
#include <glib-object.h>

G_BEGIN_DECLS

#define SIGNON_TYPE_IDENTITY             (signon_identity_get_type ())
#define SIGNON_IDENTITY(obj)             (G_TYPE_CHECK_INSTANCE_CAST ((obj), SIGNON_TYPE_IDENTITY, SignonIdentity))
#define SIGNON_IDENTITY_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST ((klass), SIGNON_TYPE_IDENTITY, SignonIdentityClass))
#define SIGNON_IS_IDENTITY(obj)          (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SIGNON_TYPE_IDENTITY))
#define SIGNON_IS_IDENTITY_CLASS(klass)  (G_TYPE_CHECK_CLASS_TYPE ((klass), SIGNON_TYPE_IDENTITY))
#define SIGNON_IDENTITY_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS ((obj), SIGNON_TYPE_IDENTITY, SignonIdentityClass))

typedef struct _SignonIdentityClass SignonIdentityClass;
typedef struct _SignonIdentityPrivate SignonIdentityPrivate;
typedef struct _SignonIdentity SignonIdentity;

/**
 * SignonIdentityClass:
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonIdentityClass
{
    GObjectClass parent_class;
};

/**
 * SignonIdentity:
 *
 * Opaque struct. Use the accessor functions below.
 */
struct _SignonIdentity
{
    GObject parent_instance;
    SignonIdentityPrivate *priv;
};

GType signon_identity_get_type (void) G_GNUC_CONST;

SignonIdentity *signon_identity_new_from_db (guint32 id);
SignonIdentity *signon_identity_new ();

guint32 signon_identity_get_id (SignonIdentity *identity);

const GError *signon_identity_get_last_error (SignonIdentity *identity);

SignonAuthSession *signon_identity_create_session(SignonIdentity *self,
                                                  const gchar *method,
                                                  GError **error);

void signon_identity_store_info (SignonIdentity *self,
                                 const SignonIdentityInfo *info,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data);
gboolean signon_identity_store_info_finish (SignonIdentity *self,
                                            GAsyncResult *res,
                                            GError **error);

void signon_identity_verify_secret (SignonIdentity *self,
                                    const gchar *secret,
                                    GCancellable *cancellable,
                                    GAsyncReadyCallback callback,
                                    gpointer user_data);
gboolean signon_identity_verify_secret_finish (SignonIdentity *self,
                                               GAsyncResult *res,
                                               GError **error);

void signon_identity_query_info (SignonIdentity *self,
                                 GCancellable *cancellable,
                                 GAsyncReadyCallback callback,
                                 gpointer user_data);
SignonIdentityInfo *signon_identity_query_info_finish (SignonIdentity *self,
                                                       GAsyncResult *res,
                                                       GError **error);

void signon_identity_remove (SignonIdentity *self,
                             GCancellable *cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data);
gboolean signon_identity_remove_finish (SignonIdentity *self,
                                        GAsyncResult *res,
                                        GError **error);

void signon_identity_sign_out (SignonIdentity *self,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data);
gboolean signon_identity_sign_out_finish (SignonIdentity *self,
                                          GAsyncResult *res,
                                          GError **error);

G_END_DECLS

#endif /* _SIGNON_IDENTITY_H_ */
