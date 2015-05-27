# Hyper Auth

Provides basic and digest authentication working on top of Hyper web client.

## How does it work

The library will execute a HEAD call against a given URL. If the response contains a WWW-Authenticate header, the value of the header will be checked. If the server requires either Basic of Digest authentication, the library will take care of it.

In case of authentication requirement, the call to authenticate will return a result of some hyper `Headers` which can be used to exeucte authenticated endpoint call.

## Usage

    extern crate hyper;
    extern crate hyper_auth;

    use hyper_auth::AuthenticationRequest;
    use hyper::Client;
    use std::io::Read;

    let method = Some("POST".to_string());
    let username = "service_username".to_string();
    let password = Some("service_password".to_string());
    let url = "http://example.com/some/service/protected/by/digest/auth".to_string();
    let da = AuthenticationRequest::new(url, username, password, method);
    match da.authenticate() {
      Ok(possibly_headers) =>
        match possibly_headers {
          Some(headers) => {
            let mut cli = Client::new();
            let mut client_response = cli.post(url).headers( headers ).send();
            // process the response here...
          },
          None => // URL not protected, just issue a call...
        },
      Err(e) => panic!(e) // this is genuine error, authentication was not attempted 
    }

## Digest authentication nonce count

The library does not fully handle the nonce count. It always issues a request with nonce count 1, subsequesnt calls do not increase it. Yet.

## License

The MIT License (MIT)

Copyright (c) 2015 Radoslaw Gruchalski <radek@gruchalski.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
