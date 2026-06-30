"use strict";

const https = require("https");

// Self-signed localhost cert for endpoint-check-worker SSL/CertOps bridge tests.
const TEST_HTTPS_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdYdLqxxTlUExG
2+NWGoagcdm3jbhbfRraWeq/9LFx01hHmAVKvJI1A27atmVx2aoAGW5En5QZ+GZ+
OOSQ8/Ab6FGObGn0iHbtWmqiHb65QoVx0oaliU1xK6jd+SpWn8qmB2h5j5Cm4jwx
7T4Zu5dwCTAfs+DDK+jjw/hjS4PWrERLBR4t5KCvlaBZODlTKKzhptbpVVNDsp01
VaQB+OmPwx6b+3Ns72aAMfc3NJb/cyZDoieVA4wwfC5vca+JAII+n1KT+q7u6Mlh
eRjC45bM0T1heXtWorJAmcrMdp3X3WM5vs+9UyLPwbTKTBAEeBNq8iPgUTrKa+7f
2oz9HxLxAgMBAAECggEAA+UFH5/OKnJl4CiGRriTaDfHtJvrv0wtoeWQ/Q+opE7q
YQ4tOQPeMInoKxPRrO3fH+TBNplGLyzXQ3cetTVrgGihEQpUMRO/RqvNa6YwX1xa
2fMvjLvkuCuFi1BZzf44Y8qsjmU2kLdUmEMyfYJHss3wEblwCIBnDAY1g2aIXw5H
FQB2+9RAwu6sOvd2N2XC0cnitFDy1lt+dqQ2H7Kxwd3xvjStaRsn04bMaaZx4psU
M2sBZGcD1+zBSrc+SAsbz7uq/gNMMcn+mg2EmODxfaup3A8ja+mSHzSw+Ipfpk8l
mAdzDsATHqjwsFqOpjnAlwdwzv2B9ikwWxE8Wb1yaQKBgQDReszoEjP3vlW9rRfZ
YmSBsKZyeAbE5JPvVmiF2o1EEn/YY4CIht1aEiGDWgPDeKgTskqqXCKLpRVJb5gO
XFGu9Cu0jogk/yZSD0a6OhmolJTHbEUQR8Ds4sWMRFeCxukk+8UFfVrumajsvbwL
IxOQBbJbMyk11RrY4mLqKFjvaQKBgQDAVTUdp3mbyrYszOpyVs6KF0kfdpBqItkE
Qlt8SVI5+iSdQgJ/wK62WmfHlCeop9lKMn5vjMBeBWKBnG6PxbkJQtavbbiJ9lwI
M0Wpmg924VJnXGtYtOU5oCEaP7FesHX6dQhEA0t1H366/kINxHm9hoLgR4Do5L66
22Pg2ACeSQKBgC3iOw2+JvnmC/vO9UFdZuxtWBgMqFbqRmkPQTfIhlbZwn0QVnAR
MlzvSb3uspJXVGF0FRy5r6tsznvWYLUMjavHuecDrViFNsyUogZagZJGcUw5L+t/
/AcnKOQveAeiMCE0sJQiQA+xQqoQaSb7WOacCNQnIaiz8/x7ofTuP4S5AoGAa3yz
LJl2Gx0U5sC2naPp1b7hvNW0K7zB7+Ft423OqFwlrkU/xEnY2kx4B0/DQjxb8V16
z7inoWP9A1Z7a5oiqQxTksMNCP1HvcV5vyk8T0HpnZ5G19Jw8N2O4m6KH9MafBh/
wBLfTtuFJdgG7k7JgqPz7IfJgV6lQSRvEy9kWRECgYALu3otlFDxtKKIzKXdzINH
43+vWvSB5i0Tswpsg73/yZZvji2lwnbVG8ucFRcShcMWjMokx//pzc4nA/4tiSKr
vQpF4gmJmutaLI+TjLUgVkNLUYXMEQh9hGR1r3ZpWwNBhRnoISHaZpugzWtqG1l6
I1hhpaPp5bOMBEa0G+RPEw==
-----END PRIVATE KEY-----`;

const TEST_HTTPS_CERT = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUeMOqzH3u0gTlhv37+vj6ZLJFXaswDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYyOTIwMzgwMFoXDTI3MDYy
OTIwMzgwMFowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAnWHS6scU5VBMRtvjVhqGoHHZt424W30a2lnqv/SxcdNY
R5gFSrySNQNu2rZlcdmqABluRJ+UGfhmfjjkkPPwG+hRjmxp9Ih27Vpqoh2+uUKF
cdKGpYlNcSuo3fkqVp/KpgdoeY+QpuI8Me0+GbuXcAkwH7Pgwyvo48P4Y0uD1qxE
SwUeLeSgr5WgWTg5Uyis4abW6VVTQ7KdNVWkAfjpj8Mem/tzbO9mgDH3NzSW/3Mm
Q6InlQOMMHwub3GviQCCPp9Sk/qu7ujJYXkYwuOWzNE9YXl7VqKyQJnKzHad191j
Ob7PvVMiz8G0ykwQBHgTavIj4FE6ymvu39qM/R8S8QIDAQABo1MwUTAdBgNVHQ4E
FgQUxZJ83uV/uTwzTwIyxQGDdztH5EswHwYDVR0jBBgwFoAUxZJ83uV/uTwzTwIy
xQGDdztH5EswDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmrSl
5PwJ9Ud1Mkx/mmgk9m7+kPZMKDiGlVt7qfjkSLwWZptkdMtN4D5LBZayuzc+4vBG
XekQfmftvWRmPtpsaKBcX6KdW3t2oXoRfVEK0Pf05Q9dZdcVS3m8BHhvbJiNQ5xP
jZ/dMCAjOvELkUoq8SXEfs3x2c4caD4BNjPhYkda09kFB41xCuF03Vv2/tB6M93U
cPl8HnQ9Ay9QEcVUrLPq4bK48j8a3Eqi4IKAu36ODWGA8fJ+VkP+iH+yE/MkcoDA
y/yoatFAUw6ABjpzjWx6caGOWsVo2nifWo9QSBCOB3BqsgAODh4YEyT/3X9if76T
UdRwPcfAgdv3+78oEQ==
-----END CERTIFICATE-----`;

// Second distinct self-signed localhost cert used to simulate certificate
// rotation at the same endpoint (different fingerprint/serial, same host/port).
const TEST_HTTPS_KEY_ROTATED = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDGXMAhOKRAO4cw
J8uGR9IDAHSk3N3l6xQalZ+Mo/LPgV+toSStCzxzQM43d0Zp9dL7oo0P/BB/Bxhm
qx6+dk4Icefsc313yilFVyAhdA/GTidxTikzVsljtJVJwsBhcT50eazEjuUErHSv
oMZ72XSyNqV5BmWUWW2duuzEIibHhdKR2TqVHN3/pFZ4x44Lb6bRt6bXyEycHLB4
ISHxyXFww2oNhlYiKtPxn1BPwcxdljZ0j5NWKoOPgZOhGvSdY9+t1KCGivjuVRDv
dgK79t7WDxMBU5o4Fuwcmmhaq+ZyrYBQK3XBQ24ygYQrcXBWdikOIdGowvQ7nQ/7
p7KGZYs/AgMBAAECggEASBcpVGmLeDSqOxwbYZ/0eVbPDaOfmZHH6ql6JNjow/VW
2nl4JNOykoh46buVgajvlrhK4AZR0Hi5q4aBU+MXFQagrVSDwudb/HFfogjWOtHo
j8tCOgBOjMfyga4f0MohUp9t5LmyDfLHLZUWzagIO0SU+tkSTcn6hpqKtfVbdqNN
7YU3puFfNtpoTYz1Wx4UoqtUw9rCFxLuaPOPOHrclY+0UAtAtCeb6yeoQk/wnXQU
r2mBgeA/eXgXhOw5OrCmxSREZeTODLY33Ier0Om36yxyU+CgXJp0ddFteZ1SOGpS
ShKpRomvkX5gLCTPC3KJ9Tn30pMYJwTcTI6BlJRykQKBgQDS3s9veFKZihiYgFzZ
UH8qD4/5DbOiiyZvWRqHHpspPBguqbjtiSQnxsXq4AxtokpcfUshblPW2SWNNyDp
w61xv02Fp5Fm8Szp+XyM/mshkepxOKrL/o3HnNafXS8EoKVSJEWt6qfyq/N/4eBy
ogiM2ST+s/KthyWpt00fZmLmwwKBgQDw0KXdpCnA0CgzmU2tGSR32WSVh1x2dJCl
jar2yS8hZnkKFHbKsSRALtoiJzL8F2aR5OLMdHLlRbOnsK5Uozh89b1H3HJm31aq
BBpCdyD6wfUQ35t0KdAnsvhk71steArcHZ0hRY+ojDr63cttRKFQtt6LwStkMlwQ
PrENk/uZ1QKBgB/LzQeH4xyXwCGuqVFzW9lhw1nQgRevV7pOezuIl+jd0N+oY+Qd
W8BLrqg95GHbqM7Nbbi6xBWPZKQofeQBx3NxXyUaIUiecSFOp0MzUcAcGne8DbT4
yzQgKBSbnm1aM9Nw+LjCu1RSLUNJMejXGebzDysAw0T7LeirZQupCpy1AoGAeWXV
l+xAGDFXctufqtl35usyp6a7WAPfP3Yxb4NwPPg5oHk8gWXXjnuP/5OfQjJRxM6L
/uHdYfNHZAvPdl9qBKSlLOrWyUFhoQe8bTE88OyCLGVtKpxBkSHJ0qhPYJaZcumC
4tj8WM2IlhrliEoGwHfPrMhOpY41lwLjoqKtPZkCgYAgRNgSvFvZ2pSkAkFcgKGz
US7zxkP755jz8dWJuGmPRoHSchtfFKXb/WLyXv0T7h/ftmiTlSXIMwBSYCUr9Nsv
SFjgOqDtInQYmNodbCWO4QvdNsfp5srVNQbg4RUfnxgqgs5/w9iceOvHt/4fM0tv
Pw1FlZQ2nyAtrfNd9kXfFQ==
-----END PRIVATE KEY-----`;

const TEST_HTTPS_CERT_ROTATED = `-----BEGIN CERTIFICATE-----
MIIDJTCCAg2gAwIBAgIUOf/5lmUdZedNoMZRjuqSBWy5aekwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDYyOTIxMjMwNloXDTI3MDYy
OTIxMjMwNlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAxlzAITikQDuHMCfLhkfSAwB0pNzd5esUGpWfjKPyz4Ff
raEkrQs8c0DON3dGafXS+6KND/wQfwcYZqsevnZOCHHn7HN9d8opRVcgIXQPxk4n
cU4pM1bJY7SVScLAYXE+dHmsxI7lBKx0r6DGe9l0sjaleQZllFltnbrsxCImx4XS
kdk6lRzd/6RWeMeOC2+m0bem18hMnByweCEh8clxcMNqDYZWIirT8Z9QT8HMXZY2
dI+TViqDj4GToRr0nWPfrdSghor47lUQ73YCu/be1g8TAVOaOBbsHJpoWqvmcq2A
UCt1wUNuMoGEK3FwVnYpDiHRqML0O50P+6eyhmWLPwIDAQABo28wbTAdBgNVHQ4E
FgQUAnzc2yYlbCa6kKyIqI4NoCOIQYMwHwYDVR0jBBgwFoAUAnzc2yYlbCa6kKyI
qI4NoCOIQYMwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAKWkt3FAgClIoocV7q9nROlkQcANX64d
3lw6hr4dGtaTb/4wsv0rczYYj5w3WKTuA6MxSMz0QD+b6pj/LDc1NoqtbeqcC5e/
AdiFCUJ4io93QDqIEk0XTWKpicBsq42al2frEtgqZN/t7OBG7sR26bA+UStHJm9n
rPQzUgwGHeyjGKG53GqRaeAhksSfRAGF6lO+GapduDjKwMg8QDFyvoisNOdOanhC
iAla+tPMsXNAjxKVvJ117EQ3+ly+vJCTvKoCw2Y6MtjRhFtDr9/F0t0JQliuCWU4
pVdkCX5AyMD6SSZ4+20GCWDyQlf4BTsB/I/zWhtFx3tWrwuxte9xyBo=
-----END CERTIFICATE-----`;

/**
 * Starts a minimal HTTPS server on 127.0.0.1 for endpoint SSL checks.
 *
 * The returned object exposes `rotateCertificate()`, which swaps the served
 * certificate in place (same host/port) so tests can simulate a cert rotation
 * at a stable monitor URL.
 *
 * @returns {Promise<{ server: import('https').Server, url: string, rotateCertificate: () => void, close: () => Promise<void> }>}
 */
function startLocalHttpsServer() {
  return new Promise((resolve, reject) => {
    const server = https.createServer(
      { key: TEST_HTTPS_KEY, cert: TEST_HTTPS_CERT },
      (_req, res) => {
        res.statusCode = 200;
        res.end("ok");
      },
    );
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve({
        server,
        url: `https://127.0.0.1:${port}`,
        rotateCertificate: () =>
          server.setSecureContext({
            key: TEST_HTTPS_KEY_ROTATED,
            cert: TEST_HTTPS_CERT_ROTATED,
          }),
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close(err => (err ? closeReject(err) : closeResolve()));
          }),
      });
    });
  });
}

module.exports = { startLocalHttpsServer };
