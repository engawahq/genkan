//! Interface languages: English, Traditional Chinese (Taiwan), Simplified Chinese.
//!
//! Messages are a typed struct with one constant per language, so a missing translation is a
//! compile error. A runtime catalogue such as Fluent would add lookup and plural rules that a
//! few dozen fixed strings without plurals or gendered text do not need. Traditional Chinese
//! uses Taiwanese terminology (通行密鑰 for passkey); Simplified Chinese uses 通行密钥.

/// A supported interface language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    /// English.
    En,
    /// Traditional Chinese as used in Taiwan.
    ZhTw,
    /// Simplified Chinese as used in mainland China.
    ZhCn,
}

impl Lang {
    /// All languages, in the order the switcher shows them.
    pub const ALL: [Self; 3] = [Self::En, Self::ZhTw, Self::ZhCn];

    /// The BCP 47 tag.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhTw => "zh-TW",
            Self::ZhCn => "zh-CN",
        }
    }

    /// The messages.
    #[must_use]
    pub const fn messages(self) -> &'static Messages {
        match self {
            Self::En => &EN,
            Self::ZhTw => &ZH_TW,
            Self::ZhCn => &ZH_CN,
        }
    }

    /// The supported language matching one BCP 47 language range, if any.
    #[must_use]
    pub fn from_range(range: &str) -> Option<Self> {
        let range = range.trim().to_ascii_lowercase();
        let mut parts = range.split('-');
        match parts.next()? {
            "en" => Some(Self::En),
            "zh" => {
                let rest: Vec<&str> = parts.collect();
                // Script subtags decide first, then regions where Traditional script is used.
                if rest.contains(&"hant") || rest.iter().any(|r| matches!(*r, "tw" | "hk" | "mo")) {
                    Some(Self::ZhTw)
                } else {
                    Some(Self::ZhCn)
                }
            }
            _ => None,
        }
    }

    /// Chooses the language: an explicit `lang` parameter wins, then the `Accept-Language` header
    /// (highest quality first, RFC 9110 §12.5.4), then English.
    #[must_use]
    pub fn negotiate(explicit: Option<&str>, accept_language: Option<&str>) -> Self {
        if let Some(lang) = explicit.and_then(Self::from_range) {
            return lang;
        }
        let mut ranges: Vec<(u16, usize, &str)> = accept_language
            .unwrap_or_default()
            .split(',')
            .take(32)
            .enumerate()
            .filter_map(|(index, item)| {
                let mut fields = item.split(';');
                let range = fields.next()?.trim();
                let quality = fields
                    .find_map(|f| f.trim().strip_prefix("q="))
                    .map_or(Some(1000), |q| qvalue(q.trim()))?;
                (quality > 0).then_some((quality, index, range))
            })
            .collect();
        ranges.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        ranges
            .iter()
            .find_map(|(_, _, range)| Self::from_range(range))
            .unwrap_or(Self::En)
    }
}

/// Parses an RFC 9110 §12.4.2 `qvalue` into thousandths: `0`, `0.5`, `0.125`, `1`, `1.000`.
fn qvalue(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let thousandths: u16 = format!("{fraction:0<3}").parse().ok()?;
    match whole {
        "0" => Some(thousandths),
        "1" if thousandths == 0 => Some(1000),
        _ => None,
    }
}

/// Every string the sign-in pages show.
#[derive(Debug)]
#[expect(
    missing_docs,
    reason = "each field is named after where its text appears; see the English values"
)]
pub struct Messages {
    pub language_name: &'static str,
    pub nav_language: &'static str,
    pub login_title: &'static str,
    pub login_subtitle: &'static str,
    pub login_continue_to: &'static str,
    pub login_username: &'static str,
    pub login_username_hint: &'static str,
    pub login_passkey: &'static str,
    pub passkey_failed: &'static str,
    pub passkey_cancelled: &'static str,
    pub passkey_unsupported_title: &'static str,
    pub passkey_unsupported_body: &'static str,
    pub noscript_title: &'static str,
    pub noscript_body: &'static str,
    pub no_request_title: &'static str,
    pub no_request_body: &'static str,
    pub working: &'static str,
    pub generic_error: &'static str,
    pub setup_title: &'static str,
    pub setup_subtitle: &'static str,
    pub setup_label: &'static str,
    pub setup_label_hint: &'static str,
    pub setup_create: &'static str,
    pub setup_done_title: &'static str,
    pub setup_done_body: &'static str,
    pub setup_invalid: &'static str,
    pub setup_missing_token: &'static str,
    pub error_title: &'static str,
    pub error_body: &'static str,
    pub error_detail_label: &'static str,
    pub continue_with: &'static str,
    pub upstream_or: &'static str,
    pub upstream_linked_title: &'static str,
    pub upstream_linked_body: &'static str,
    pub upstream_not_linked: &'static str,
    pub upstream_failed: &'static str,
    pub upstream_already_linked: &'static str,
}

/// English.
pub const EN: Messages = Messages {
    language_name: "English",
    nav_language: "Language",
    login_title: "Sign in",
    login_subtitle: "Use the passkey on this device or on your phone.",
    login_continue_to: "Continue to",
    login_username: "Username",
    login_username_hint: "Optional. Your browser can suggest your passkey here.",
    login_passkey: "Sign in with a passkey",
    passkey_failed: "That passkey could not be verified. Try again.",
    passkey_cancelled: "Sign-in was cancelled.",
    passkey_unsupported_title: "This browser cannot use passkeys",
    passkey_unsupported_body: "Use a current version of Safari, Chrome, Edge or Firefox, or open this page on your phone.",
    noscript_title: "JavaScript is required",
    noscript_body: "Passkeys need JavaScript. Turn it on for this site and reload the page.",
    no_request_title: "Nothing to sign in to",
    no_request_body: "Start from the application or command you want to use, such as kubectl. It will send you here.",
    working: "Waiting for your passkey…",
    generic_error: "Something went wrong. Try again.",
    setup_title: "Set up your passkey",
    setup_subtitle: "This one-time link lets you register a passkey for your account.",
    setup_label: "Name for this passkey",
    setup_label_hint: "Optional. Helps you recognise it later, for example “Work laptop”.",
    setup_create: "Create passkey",
    setup_done_title: "Passkey created",
    setup_done_body: "You can close this page. Sign in from your application, or from kubectl, with this passkey.",
    setup_invalid: "This setup link is invalid, used or expired. Ask your cluster administrator for a new one.",
    setup_missing_token: "Open the complete setup link, including the part after “#”.",
    error_title: "This sign-in cannot continue",
    error_body: "Return to the application and start again. If this keeps happening, contact your administrator.",
    error_detail_label: "Details",
    continue_with: "Continue with",
    upstream_or: "or",
    upstream_linked_title: "Account linked",
    upstream_linked_body: "From now on you can sign in with this account. You can close this page.",
    upstream_not_linked: "This account is not linked to any user here. Ask your administrator for an invitation, then link the account from it.",
    upstream_failed: "Signing in with the provider did not work. Start again from your application.",
    upstream_already_linked: "This account is already linked to a user.",
};

/// Traditional Chinese (Taiwan).
pub const ZH_TW: Messages = Messages {
    language_name: "繁體中文",
    nav_language: "語言",
    login_title: "登入",
    login_subtitle: "使用這台裝置或手機上的通行密鑰。",
    login_continue_to: "繼續前往",
    login_username: "使用者名稱",
    login_username_hint: "可留空。瀏覽器會在這裡建議你的通行密鑰。",
    login_passkey: "使用通行密鑰登入",
    passkey_failed: "無法驗證這個通行密鑰，請再試一次。",
    passkey_cancelled: "已取消登入。",
    passkey_unsupported_title: "這個瀏覽器無法使用通行密鑰",
    passkey_unsupported_body: "請改用新版的 Safari、Chrome、Edge 或 Firefox，或在手機上開啟這個頁面。",
    noscript_title: "需要啟用 JavaScript",
    noscript_body: "通行密鑰需要 JavaScript。請為這個網站啟用後重新載入頁面。",
    no_request_title: "目前沒有要登入的服務",
    no_request_body: "請從要使用的應用程式或指令（例如 kubectl）開始，它會把你帶到這裡。",
    working: "正在等待通行密鑰…",
    generic_error: "發生錯誤，請再試一次。",
    setup_title: "設定通行密鑰",
    setup_subtitle: "透過這個一次性連結，為你的帳號註冊通行密鑰。",
    setup_label: "通行密鑰名稱",
    setup_label_hint: "可留空。方便日後辨認，例如「公司筆電」。",
    setup_create: "建立通行密鑰",
    setup_done_title: "已建立通行密鑰",
    setup_done_body: "可以關閉這個頁面了。之後請在應用程式或 kubectl 中使用這個通行密鑰登入。",
    setup_invalid: "這個設定連結無效、已使用或已過期，請向叢集管理員索取新的連結。",
    setup_missing_token: "請開啟完整的設定連結，包括「#」後面的部分。",
    error_title: "無法繼續這次登入",
    error_body: "請回到應用程式重新開始。如果問題持續發生，請聯絡管理員。",
    error_detail_label: "詳細資訊",
    continue_with: "使用以下帳號繼續：",
    upstream_or: "或",
    upstream_linked_title: "帳號已連結",
    upstream_linked_body: "之後可以用這個帳號登入。你可以關閉此頁面。",
    upstream_not_linked: "這個帳號尚未連結到任何使用者。請向管理員索取邀請，再從邀請中連結帳號。",
    upstream_failed: "透過外部帳號登入沒有成功。請從你的應用程式重新開始。",
    upstream_already_linked: "這個帳號已經連結到某位使用者。",
};

/// Simplified Chinese.
pub const ZH_CN: Messages = Messages {
    language_name: "简体中文",
    nav_language: "语言",
    login_title: "登录",
    login_subtitle: "使用此设备或手机上的通行密钥。",
    login_continue_to: "继续前往",
    login_username: "用户名",
    login_username_hint: "可留空。浏览器会在这里推荐你的通行密钥。",
    login_passkey: "使用通行密钥登录",
    passkey_failed: "无法验证此通行密钥，请重试。",
    passkey_cancelled: "已取消登录。",
    passkey_unsupported_title: "此浏览器无法使用通行密钥",
    passkey_unsupported_body: "请使用最新版的 Safari、Chrome、Edge 或 Firefox，或在手机上打开此页面。",
    noscript_title: "需要启用 JavaScript",
    noscript_body: "通行密钥需要 JavaScript。请为此网站启用后重新加载页面。",
    no_request_title: "当前没有需要登录的服务",
    no_request_body: "请从要使用的应用或命令（例如 kubectl）开始，它会把你带到这里。",
    working: "正在等待通行密钥…",
    generic_error: "出现错误，请重试。",
    setup_title: "设置通行密钥",
    setup_subtitle: "通过此一次性链接，为你的账户注册通行密钥。",
    setup_label: "通行密钥名称",
    setup_label_hint: "可留空。便于日后辨认，例如“工作笔记本”。",
    setup_create: "创建通行密钥",
    setup_done_title: "已创建通行密钥",
    setup_done_body: "现在可以关闭此页面。之后请在应用或 kubectl 中使用此通行密钥登录。",
    setup_invalid: "此设置链接无效、已使用或已过期，请向集群管理员索取新链接。",
    setup_missing_token: "请打开完整的设置链接，包括“#”之后的部分。",
    error_title: "无法继续此次登录",
    error_body: "请返回应用重新开始。如果问题持续出现，请联系管理员。",
    error_detail_label: "详细信息",
    continue_with: "使用以下账号继续：",
    upstream_or: "或",
    upstream_linked_title: "账号已关联",
    upstream_linked_body: "之后可以用这个账号登录。你可以关闭此页面。",
    upstream_not_linked: "这个账号尚未关联到任何用户。请向管理员索取邀请，再从邀请中关联账号。",
    upstream_failed: "通过外部账号登录没有成功。请从你的应用重新开始。",
    upstream_already_linked: "这个账号已经关联到某个用户。",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        assert_eq!(Lang::negotiate(None, None), Lang::En);
        assert_eq!(Lang::negotiate(Some("zh-TW"), Some("en")), Lang::ZhTw);
        assert_eq!(
            Lang::negotiate(Some("fr"), Some("zh-CN")),
            Lang::ZhCn,
            "unsupported explicit falls through"
        );
        assert_eq!(
            Lang::negotiate(None, Some("zh-Hant-HK,en;q=0.5")),
            Lang::ZhTw
        );
        assert_eq!(Lang::negotiate(None, Some("zh-Hans")), Lang::ZhCn);
        assert_eq!(Lang::negotiate(None, Some("zh")), Lang::ZhCn);
        assert_eq!(
            Lang::negotiate(None, Some("fr, en;q=0.4, zh-TW;q=0.8")),
            Lang::ZhTw,
            "by quality"
        );
        assert_eq!(
            Lang::negotiate(None, Some("zh-TW;q=0, en")),
            Lang::En,
            "q=0 excluded"
        );
        assert_eq!(Lang::negotiate(None, Some("de")), Lang::En);
    }

    #[test]
    fn qvalues() {
        assert_eq!(qvalue("1"), Some(1000));
        assert_eq!(qvalue("1.000"), Some(1000));
        assert_eq!(qvalue("0.5"), Some(500));
        assert_eq!(qvalue("0.125"), Some(125));
        assert_eq!(qvalue("0"), Some(0));
        for bad in ["", "1.5", "2", "0.1234", "-0", "0.-1", "abc", ".5"] {
            assert_eq!(qvalue(bad), None, "{bad}");
        }
    }

    #[test]
    fn negotiate_never_panics_on_garbage() {
        for input in ["", ",,,", ";q=", "zh;q=abc", "*;q=0.5", &"x,".repeat(1000)] {
            assert!(Lang::ALL.contains(&Lang::negotiate(Some(input), Some(input))));
        }
    }

    #[test]
    fn every_language_has_text() {
        for lang in Lang::ALL {
            let m = lang.messages();
            assert!(
                !m.login_title.is_empty() && !m.setup_done_body.is_empty(),
                "{lang:?}"
            );
        }
    }
}
