
# remote-iap

This is a fork of [git-remote-https+iap](https://github.com/adohkan/git-remote-https-iap/) to support a few more use cases for Gcloud IAP auth tokens.
While [google-api-go-client](https://github.com/googleapis/google-api-go-client/issues/873) supports service accounts, this tool is for user authentication.

For example, after [configuring](#configuring):

```
curl -v -H "Authorization: Bearer $(DEBUG=true remote-iap print https://iap.example.net)" https://iap.example.net
```

Multiple domains can use the same authentication, if they share an IDP client.

To use the binary as [gitremote helper](https://www.git-scm.com/docs/gitremote-helpers)
rename or symlink to `git-remote-iap` and use `--helperName=iap` when running `configure`.

# git-remote-https+iap

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/adohkan/git-remote-https-iap)](https://github.com/adohkan/git-remote-https-iap/releases/latest)
[![GitHub](https://img.shields.io/github/license/adohkan/git-remote-https-iap)](LICENSE.txt)
[![Go Report Card](https://goreportcard.com/badge/github.com/adohkan/git-remote-https-iap)](https://goreportcard.com/report/github.com/adohkan/git-remote-https-iap)

An open source [`git-remote-helper`](https://www.git-scm.com/docs/gitremote-helpers) that handles authentication for [GCP Identity Aware Proxy](https://cloud.google.com/iap).

## Getting Started

### Installing

(Edited from upstream, see also https://github.com/adohkan/git-remote-https-iap#installing)

- Download pre-compiled binaries from [`our release page`](https://github.com/solsson/remote-iap/releases).
- Install `git-remote-iap` binary onto the system `$PATH`
- Run `GIT_IAP_VERBOSE=1 git-remote-iap install`

### Configuring

- [Generate OAuth credentials FOR THE HELPER](https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_a_desktop_app)[1]
- Configure the IAP protected repositories:

```
git-remote-iap configure \
  --helperName=iap \
  --repoURL=https://git.domain.acme/demo/hello-world.git \
  --helperID=xxx \
  --helperSecret=yyy \
  --clientID=zzz
```

**Notes**:
* In the example above, `xxx` and `yyy` are the OAuth credentials FOR THE HELPER, that needs to be created as instructed [here](https://cloud.google.com/iap/docs/authentication-howto#authenticating_from_a_desktop_app). `zzz` is the OAuth client ID that has been created when your Identity Aware Proxy instance has been created.
* All repositories served on the same domain (`git.domain.acme`) would share the same configuration


[1]: This needs to be done only once per _organisation_. While [these credentials are not treated as secret](https://developers.google.com/identity/protocols/oauth2#installed) and can be shared within your organisation, [it seem forbidden to publish them in any open source project](https://stackoverflow.com/questions/27585412/can-i-really-not-ship-open-source-with-client-id).

### Usage

Once your domain has been configured, you should be able to use `git` as you would normally do, without thinking about the IAP layer.

```
$ git clone https://git.domain.acme/demo/hello-world.git
```

> If you are using [`git-lfs`](https://git-lfs.github.com/), the minimal version requirement is [`>= v2.9.0`](https://github.com/git-lfs/git-lfs/releases/), which introduced support of HTTP cookies.

### Troubleshoot

If needed, you can set the `GIT_IAP_VERBOSE=1` environment variable in order to increase the verbosity of the logs.
