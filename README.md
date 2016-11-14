# enenra

An Erlang/OTP library for interfacing with Google Cloud Storage. Named after the [smoke monster](https://en.wikipedia.org/wiki/Enenra) of Japanese folklore, for no particular reason.

## Requirements

* [Erlang/OTP](http://www.erlang.org) R17 or higher
* [rebar3](https://github.com/erlang/rebar3/) 3.0.0 or higher

## Building and Testing

```
$ rebar3 compile
$ rebar3 ct
```

## TODO

1. Implement CRUD operations for objects.
1. Ensure bucket names meet at least some of the many [requirements](https://cloud.google.com/storage/docs/naming#requirements).
1. Support other forms of authorization?
1. Add code examples to the README and API overview page.

## Example Usage

Including as a dependency in your release, using rebar...

```
{deps, [
    {enenra, {git, "https://github.com/nlfiedler/enenra", {tag, "0.1.0"}}}
]}.
```

Be sure to include `enenra` in the `included_applications` list of your application configuration before building a release.

## Google Cloud Setup

1. Visit https://console.cloud.google.com/ and log in with your account.
1. Select an existing project or create a new one.
1. Note the *Project ID* as that will be necessary when connecting via enenra.
1. Using the menu, select **API Manager**, then **Credentials**.
1. On the **Credentials** page, select the **Create credentials** drop-down, then select **Service account key**.
1. From the **Service** account drop-down, select an existing service account or create a new one.
1. For **Key** type, select the **JSON** key option, then select **Create**. The file automatically downloads to your computer.
1. Put the `*.json` file you just downloaded in a directory of your choosing. This directory must be private, but accessible to your application.

## License

[BSD 3-Clause](https://opensource.org/licenses/BSD-3-Clause), see the `LICENSE` file.
