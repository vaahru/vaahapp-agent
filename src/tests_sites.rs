//! Website discovery parsers, with config samples in the shapes our servers produce.

use crate::collect::{caddy, sites};

fn names(v: &[crate::report::Site]) -> Vec<String> {
    v.iter().map(|s| format!("{}:{}{}", s.domain, if s.tls { "tls" } else { "plain" }, if s.wildcard { ":wild" } else { "" })).collect()
}

#[test]
fn nginx_t_cloudpanel_and_plain() {
    // `nginx -T` prints each file after a "# configuration file" comment; included vhost files hold bare
    // server blocks at their top level.
    let t = r#"
# configuration file /etc/nginx/nginx.conf:
user www-data;
events { worker_connections 1024; }
http {
    upstream php { server 127.0.0.1:9000; }
    server {
        listen 80 default_server;
        server_name _;
        return 444;
    }
    include /etc/nginx/sites-enabled/*;
}
stream {
    server { listen 3307; proxy_pass db:3306; }
}
# configuration file /etc/nginx/sites-enabled/example.com.conf:
server {
  listen 80;
  listen [::]:80;
  server_name example.com www.example.com;
  return 301 https://example.com$request_uri;
}
server {
  listen 443 quic;
  listen 443 ssl;
  http2 on;
  server_name example.com www.example.com;   # main site
  location / { try_files $uri /index.php?$args; }
  location ~ \.php$ { fastcgi_pass php; }
}
# configuration file /etc/nginx/sites-enabled/shop.conf:
server {
    listen 8080;
    server_name shop.example.org *.cdn.example.org ~^(?<sub>.+)\.regex\.org$ 10.0.0.5 localhost;
}
"#;
    let got = names(&sites::merge(sites::parse_nginx(t)));
    assert_eq!(got, vec!["cdn.example.org:plain:wild", "example.com:tls", "shop.example.org:plain", "www.example.com:tls"]);
}

#[test]
fn apache_s_output() {
    let s = "VirtualHost configuration:
*:443                  is a NameVirtualHost
         default server site.ru (/etc/apache2/sites-enabled/site-ssl.conf:2)
         port 443 namevhost site.ru (/etc/apache2/sites-enabled/site-ssl.conf:2)
                 alias www.site.ru
         port 443 namevhost shop.site.ru (/etc/apache2/sites-enabled/shop.conf:1)
*:80                   old.site.ru (/etc/apache2/sites-enabled/old.conf:1)
ServerRoot: \"/etc/apache2\"
";
    assert_eq!(names(&sites::merge(sites::parse_apache(s))), vec!["old.site.ru:plain", "shop.site.ru:tls", "site.ru:tls", "www.site.ru:tls"]);
}

#[test]
fn caddyfile_sites_and_imports() {
    let c = r#"
{
	email admin@example.com
	servers { trusted_proxies static 10.77.0.0/24 }
}
(common) {
	encode gzip
}
app.vaah.ru, www.vaah.ru {
	reverse_proxy app:80 {
		header_up X-Real-IP {client_ip}
	}
}
http://plain.example.com {
	respond "hi"
}
:8080 {
	respond "internal"
}
{$SITE_DOMAIN} {
	respond "env"
}
import sites.d/*.caddy
"#;
    let (s, imports) = caddy::parse(c);
    assert_eq!(names(&s), vec!["app.vaah.ru:tls", "www.vaah.ru:tls", "plain.example.com:plain"]);
    assert_eq!(imports, vec!["sites.d/*.caddy"]);
}

#[test]
fn caddy_import_maps_container_paths() {
    let dir = std::env::temp_dir().join(format!("vah-caddy-{}", std::process::id()));
    let sd = dir.join("sites.d");
    std::fs::create_dir_all(&sd).unwrap();
    std::fs::write(sd.join("a.caddy"), "a.example.com {\n}\n").unwrap();
    std::fs::write(sd.join("b.caddy"), "b.example.com {\n}\n").unwrap();
    std::fs::write(sd.join("notes.txt"), "x").unwrap();
    // Container mounts: Caddyfile and sites.d separately; relative import resolves via the mounts.
    let mounts = vec![
        ("/etc/caddy/Caddyfile".to_string(), dir.join("Caddyfile").display().to_string()),
        ("/etc/caddy/sites.d".to_string(), sd.display().to_string()),
    ];
    let files = caddy::expand_import("sites.d/*.caddy", std::path::Path::new("/nonexistent"), &mounts);
    let n: Vec<String> = files.iter().map(|f| f.file_name().unwrap().to_string_lossy().into_owned()).collect();
    assert_eq!(n, vec!["a.caddy", "b.caddy"]);
    // Host Caddyfile: relative to its directory.
    assert_eq!(caddy::expand_import("sites.d/*.caddy", &dir, &[]).len(), 2);
    // Container path with no mount: nothing (never read the agent host's own /etc).
    assert!(caddy::expand_import("/etc/other/x.caddy", &dir, &mounts).is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}
