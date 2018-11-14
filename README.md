# enenra

An Erlang/OTP library for interfacing with Google Cloud Storage. Named after the [smoke monster](https://en.wikipedia.org/wiki/Enenra) of Japanese folklore, for no particular reason. This library provides basic CRUD operations on buckets and objects, including uploading and downloading of object media.

## Requirements

* [Erlang/OTP](http://www.erlang.org) R18 or R19
    * R20 has backward incompatible API changes
* [rebar3](https://github.com/erlang/rebar3/) 3.0.0 or higher

## Building and Testing

```
$ rebar3 compile
$ export GOOGLE_APPLICATION_CREDENTIALS=~/.your_gcp_credentials.json
$ rebar3 ct
```

Note that the test suite expects to find an environment variable named `GOOGLE_APPLICATION_CREDENTIALS` which specifies the path to your Google Cloud Platform service credentials. This JSON formatted file is created via the Cloud Console, as described in the setup section below. This file contains your private key, so be sure to store this file with permissions that prevent exposure to third parties.

## Example Usage

To include `enenra` as a dependency in your release, add it to the list of dependencies in your `rebar.config` file, like so:

```
{deps, [
    {enenra, {git, "https://github.com/nlfiedler/enenra", {tag, "0.2.0"}}}
]}.
```

To have the `enenra` application started automatically, be sure to include `enenra` in the `applications` list of your application configuration before building a release. You may also want to add `jiffy` to the list of `included_applications`, and `hackney` to the list of `applications`.

Below is a simple example in which a bucket is created and a file is uploaded to that bucket. This also demonstrates loading the credentials from a file and computing an MD5 checksum of a file to be uploaded to a bucket.

```erlang
1> rr("include/enenra.hrl").
[access_token,bucket,credentials,object]
2> application:ensure_all_started(enenra).
{ok,[idna,mimerl,certifi,ssl_verify_fun,metrics,hackney,enenra]}
3> Credentials = os:getenv("GOOGLE_APPLICATION_CREDENTIALS").
"/Users/nfiedler/.gcloud/testing.json"
4> {ok, Creds} = enenra:load_credentials(Credentials).
{ok,#credentials{type = <<"service_account">>,
                 project_id = <<"a-project">>,
                 private_key_id = <<"a-private-key-id">>,
                 private_key = <<"a-private-key">>,
                 client_email = <<"an-email-address">>,
                 client_id = <<"a-client-id">>}}
5> enenra:insert_bucket(#bucket{
    name = <<"0136d00f-a942-11e6-8f9a-3c07547e18a6-enenra-1234">>,
    location = <<"US-WEST1">>,
    storageClass = <<"STANDARD">>}, Creds).
{ok,#bucket{id = <<"a-bucket-id">>,
            projectNumber = <<"a-project-number">>,
            name = <<"0136d00f-a942-11e6-8f9a-3c07547e18a6-enenra-1234">>,
            timeCreated = <<"2016-11-18T22:25:54.239Z">>,
            updated = <<"2016-11-18T22:25:54.239Z">>,
            location = <<"US-WEST1">>,
            storageClass = <<"STANDARD">>}}
6> {ok, Md5} = enenra:compute_md5("test/enenra_SUITE_data/IMG_5745.JPG").
{ok,<<"kq56YDAH2p4mzAqrQw84kQ==">>}
7> enenra:upload_file("test/enenra_SUITE_data/IMG_5745.JPG", #object{
    name = <<"my_image">>,
    bucket = <<"0136d00f-a942-11e6-8f9a-3c07547e18a6-enenra-1234">>,
    contentType = <<"image/jpeg">>,
    md5Hash = Md5,
    size = 107302}, Creds).
{ok,#object{id = <<"a-bucket-id/name/an-object-id">>,
            name = <<"my_image">>,
            bucket = <<"0136d00f-a942-11e6-8f9a-3c07547e18a6-enenra-1234">>,
            contentType = <<"image/jpeg">>,
            timeCreated = <<"2016-11-18T22:28:01.232Z">>,
            updated = <<"2016-11-18T22:28:01.232Z">>,
            storageClass = <<"STANDARD">>,
            size = <<"107302">>,
            md5Hash = <<"kq56YDAH2p4mzAqrQw84kQ==">>}}
```

## Google Cloud Setup

1. Visit https://console.cloud.google.com/ and log in with your account.
1. Select an existing project or create a new one.
1. Note the *Project ID* as that will be necessary when connecting via enenra.
1. Using the menu, select **API Manager**, then **Credentials**.
1. On the **Credentials** page, select the **Create credentials** drop-down, then select **Service account key**.
1. From the **Service** account drop-down, select an existing service account or create a new one.
1. For **Key** type, select the **JSON** key option, then select **Create**. The file automatically downloads to your computer.
1. Put the `*.json` file you just downloaded in a directory of your choosing. This directory must be private, but accessible to your application.

## Security

The credentials file must be readable by the application, but should not be readable by casual users. Likewise, it is possible, if the server process crashes, that the private keys will end up in the log file (they are an argument to the API, after all). As such, the log files should be protected from unintended exposure to third parties.

## License

[BSD 3-Clause](https://opensource.org/licenses/BSD-3-Clause), see the `LICENSE` file.
