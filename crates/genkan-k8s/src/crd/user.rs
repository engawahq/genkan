//! `User`: a person who can sign in.

#![expect(
    unreachable_pub,
    reason = "the KubeSchema derive re-emits these types inside a private module"
)]

use kube::{CustomResource, KubeSchema};
use serde::{Deserialize, Serialize};

/// A person who can sign in. The admin (or GitOps) owns `spec`; Genkan writes only `status`.
///
/// Kubernetes sees the user as `genkan:<username>` with groups `genkan:<group>`.
#[derive(
    CustomResource, KubeSchema, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq,
)]
#[kube(
    group = "genkan.engawahq.dev",
    version = "v1alpha1",
    kind = "User",
    namespaced,
    status = "UserStatus",
    shortname = "gkuser",
    category = "genkan",
    selectable = ".spec.username",
    printcolumn(name = "Username", type_ = "string", json_path = ".spec.username"),
    printcolumn(name = "Disabled", type_ = "boolean", json_path = ".spec.disabled"),
    printcolumn(
        name = "Age",
        type_ = "date",
        json_path = ".metadata.creationTimestamp"
    ),
    doc = "A person who can sign in to Genkan."
)]
#[serde(rename_all = "camelCase")]
pub struct UserSpec {
    /// Login name: a lowercase DNS subdomain of at most 128 characters. Kubernetes sees
    /// `genkan:<username>`. Use the username as the object name so object-name uniqueness
    /// also prevents duplicate usernames. Immutable because RBAC bindings and audit logs
    /// refer to it.
    #[schemars(
        length(min = 1, max = 128),
        regex(pattern = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$")
    )]
    #[x_kube(validation = Rule::new("self == oldSelf").message("username is immutable"))]
    pub username: String,

    /// Name shown in the UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(max = 128))]
    pub display_name: Option<String>,

    /// Groups. Kubernetes sees each as `genkan:<group>`. The characters exclude ':', so a group
    /// can never spell a reserved or elevated name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
        length(max = 64),
        inner(
            length(min = 1, max = 128),
            regex(pattern = r"^[a-z0-9]([-a-z0-9._/]{0,126}[a-z0-9])?$")
        )
    )]
    pub groups: Vec<String>,

    /// A disabled user cannot sign in, and refresh tokens stop working at their next use.
    #[serde(default)]
    pub disabled: bool,

    /// Groups the user can take on for a few minutes after a fresh passkey sign-in that asks for
    /// the `elevate` scope, when elevation is enabled. Kubernetes sees each as
    /// `genkan:elevated:<group>`; bind powerful roles only to those names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(
        length(max = 16),
        inner(
            length(min = 1, max = 128),
            regex(pattern = r"^[a-z0-9]([-a-z0-9._/]{0,126}[a-z0-9])?$")
        )
    )]
    pub elevated_groups: Vec<String>,
}

/// Runtime state written by Genkan through the status subresource.
#[derive(KubeSchema, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UserStatus {
    /// Incremented to sign the user out of every browser session.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub session_epoch: i64,
    /// Incremented when a recovery or enrollment link is used, which invalidates every other
    /// outstanding link.
    #[serde(default)]
    #[schemars(range(min = 0))]
    pub recovery_epoch: i64,
    /// When the user last signed in, in Unix seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub last_sign_in_at: Option<i64>,
}
