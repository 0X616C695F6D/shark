import torch

from transformers import RobertaTokenizer, RobertaForSequenceClassification


network_packet = """
Connection Details:
Source: [REDACTED]
Dest: [REDACTED]
Protocol: TCP
=== Payload Data ===

<--- Packet1 ---


<--- Packet2 ---


<--- Packet3 ---
HTTP/1.1 200 OK..Age: 604018..Cache-Control: max-age=604800..Content-Type:
text/html; charset=UTF-8..Date: Mon, 06 Jan 2025 19:46:15 GMT..Etag:
"3147526947+gzip+ident"..Expires: Mon, 13 Jan 2025 19:46:15 GMT..Last-Modified:
Thu, 17 Oct 2019 07:18:26 GMT..Server: ECAcc (agb/5394)..Vary:
Accept-Encoding..X-Cache: HIT..Content-Length: 1256....<!doctype
html>.<html>.<head>.    <title>Example Domain</title>..    <meta
charset="utf-8" />.    <meta http-equiv="Content-type" content="text/html;
charset=utf-8" />.    <meta name="viewport" content="width=device-width,
initial-scale=1" />.    <style type="text/css">.    body {.
background-color: #f0f0f2;.        margin: 0;.        padding: 0;.
font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe
UI", "Open Sans", "Helvetica Neue", Helvetica, Arial, sans-serif;.
.    }.    div {.        width: 600px;.        margin: 5em auto;.
padding: 2em;.        background-color: #fdfdff;.
border-radius: 0.5em;.        box-shadow: 2px 3px 7px 2px
rgba(0,0,0,0.02);.    }.    a:link, a:visited {.
color: #38488f;.        text-decoration: none;.
}.    @media (max-width: 700px) {.        div {.
margin: 0 auto;.            width: auto;.
}.    }.    </style>    .</head>..<body>.<div>.
<h1>Example Domain</h1>.    <p>This domain is for
use in illustrative examples in documents. You may
use this.    domain in literature without prior
coordination or asking for permission.</p>.    <p><a
href="https://www.iana.org/domains/example">More
information...</a></p>.</div>.</body>.</html>.

<--- Packet4 ---
"""


tokenizer = RobertaTokenizer.from_pretrained("roberta-base")
model = RobertaForSequenceClassification.from_pretrained("roberta-base", num_labels=2)

inputs = tokenizer("Is this packet malicious or benign: {network_packet}", return_tensors="pt")
outputs = model(**inputs)

logits = outputs.logits
predicted_class = logits.argmax(dim=-1).item()

labels = ["benign", "malicious"]
print(f"Logits: {logits}\nPrediction: {labels[predicted_class]}")
