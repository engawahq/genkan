#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod cli;
mod output;

use std::process::ExitCode;

use clap::Parser as _;
use genkan_core::clock::Clock as _;

use crate::cli::{
    Cli, ClientCommand, ClientCreateArgs, ClientKind, Command, InviteArgs, KubeConfigArgs,
    SetupLinkArgs, SigningAlg,
};

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::SetupLink(args) => setup_link(&args),
        Command::Crds => print_json(genkan_k8s::crd::definitions_json()),
        Command::Rbac { namespace } => print_json(genkan_k8s::rbac::manifests_json(&namespace)),
        Command::Manifests(args) => print_json(genkan_k8s::deployment::manifests_json(
            &args.namespace,
            &args.issuer,
            &genkan_k8s::deployment::Options {
                image: args.image.clone(),
                serve_args: args.serve_args.clone(),
                config_secret: args.config_secret.clone(),
            },
        )),
        Command::KubeConfig(args) => kube_config(&args),
        Command::Invite(args) => invite(&args),
        Command::Client {
            command: ClientCommand::Create(args),
        } => client_create(args),
    }
}

fn client_create(args: ClientCreateArgs) -> ExitCode {
    use genkan_k8s::crd::client::ClientType;
    let new = genkan_k8s::clients::NewClient {
        kind: match args.kind {
            ClientKind::Public => ClientType::Public,
            ClientKind::Confidential => ClientType::Confidential,
        },
        id_token_signing_alg: args.id_token_signing_alg.map(|alg| match alg {
            SigningAlg::Es256 => genkan_keys::Algorithm::Es256,
            SigningAlg::Rs256 => genkan_keys::Algorithm::Rs256,
        }),
        client_id: args.client_id,
        display_name: args.display_name,
        redirect_uris: args.redirect_uris,
        audiences: args.audiences,
        allow_elevation: args.allow_elevation,
    };
    let registration = match genkan_k8s::clients::register(new, &args.namespace) {
        Ok(registration) => registration,
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            return ExitCode::FAILURE;
        }
    };
    let code = print_json(serde_json::to_string_pretty(&registration.client));
    if let Some(secret) = registration.secret {
        output::stderr(
            "Client secret (shown only now; it cannot be recovered from the cluster, only replaced):",
        );
        output::stderr(&secret);
    }
    code
}

fn invite(args: &InviteArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let invitee = genkan_k8s::invitations::Invitee {
        username: args.username.clone(),
        display_name: args.display_name.clone(),
        groups: args.groups.clone(),
        elevated_groups: args.elevated_groups.clone(),
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        genkan_k8s::invitations::invite(
            client,
            &args.namespace,
            &args.issuer,
            &invitee,
            args.valid_for,
            genkan_core::clock::SystemClock.now(),
        )
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    });
    match result {
        Ok(created) => {
            if !created.created_user {
                output::stderr(&format!(
                    "User {} already exists; its groups were not changed.",
                    args.username
                ));
            }
            output::stdout(&created.url);
            output::stderr(&format!(
                "Send this link to {}. It works once and expires in {} days.",
                args.username,
                args.valid_for.as_secs() / 86_400
            ));
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn current_thread_runtime() -> Option<tokio::runtime::Runtime> {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => Some(runtime),
        Err(error) => {
            output::stderr(&format!("error: starting the async runtime: {error}"));
            None
        }
    }
}

fn kube_config(args: &KubeConfigArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let request = genkan_k8s::kube_config::Request {
        namespace: args.namespace.clone(),
        distro: args.distro,
        issuer: args.issuer.clone(),
        discovery: args.discovery,
        audiences: args.audiences.clone(),
        max_token_lifetime: args.max_token_lifetime,
        max_elevated_token_lifetime: args.max_elevated_token_lifetime,
        renew: args.renew_certificate,
        certificate_validity: args.certificate_validity,
        now: genkan_core::clock::SystemClock.now(),
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        genkan_k8s::kube_config::prepare(client, &request)
            .await
            .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    });
    match result {
        Ok(prepared) => {
            output::stdout(prepared.configuration.trim_end());
            if let Some(until) = prepared.issued_until {
                output::stderr(&format!(
                    "Issued a new internal certificate, valid until Unix time {} ({} days). Re-run this command before then.",
                    until.as_secs(),
                    args.certificate_validity.as_secs() / 86_400
                ));
            }
            output::stderr(
                genkan_k8s::kube_config::instructions(args.distro, args.discovery).trim_end(),
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn setup_link(args: &SetupLinkArgs) -> ExitCode {
    let Some(runtime) = current_thread_runtime() else {
        return ExitCode::FAILURE;
    };
    let result = runtime.block_on(async {
        let client = kube::Client::try_default().await?;
        let now = genkan_core::clock::SystemClock.now();
        genkan_k8s::setup::issue_setup_link(
            client,
            &args.namespace,
            &args.issuer,
            &args.username,
            args.valid_for,
            args.reset,
            now,
        )
        .await
        .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })
    });
    match result {
        Ok(link) => {
            output::stdout(&link.url);
            output::stderr(&format!(
                "This link enrols a passkey for {}. It works once and expires in {} minutes. Open it in a browser.",
                args.username,
                args.valid_for.as_secs() / 60
            ));
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn print_json(json: serde_json::Result<String>) -> ExitCode {
    match json {
        Ok(json) => {
            output::stdout(&json);
            ExitCode::SUCCESS
        }
        Err(error) => {
            output::stderr(&format!("error: {error}"));
            ExitCode::FAILURE
        }
    }
}
