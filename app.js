var express = require('express');
var server = express();
const cors = require('cors');
const request = require('request');
const crypto = require('crypto');
server.use(express.json())
server.use(cors({
    origin: ['http://localhost:3000', 'https://comprecripto.io/']
}));
server.listen(3002, () => {
    console.log("server listen on 3002")
});

const getHeaders = (body) => {
    const privateKeyString = "308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100bc36b5f4d2a94dca82164d4bf99e73dd1423927e0ce73d262a5210a41c472c87dfd7be1030b19ffbe2ee0efe68bac72a6f302f0bbc9c233850dc1048175af0cae5c918bbc9c9f4cf8116fc3a525d823f0b8f75f0655153002e30f59dbb8734c25a9299cf897cf15cbe94e02387efa32c0440e99508948b1196d5309e975dc3d2e3901d98f6dc9af2fc9759d8f7c2c65bf6fb194aea2715d2757c04d05d92b6e3bc01bb3912d832ad527bfcb4bef161d54efe18a294e9e5a5e67ffa2b49db12c00956913f59879d6877424e7e6c95868ae3c641bf2b6aaa86e6086e25f48c689524f0c12cc0b74041a3a7ed99aeb333789a6e4c3c4429200bacb71f51f4eeb39d0203010001028201001038f3fe7de0d76266cb86ce8f5da3b570bcaf2dfbad3bb54c2d061fab0b4c708aafe5032ebb44a39897f5c5626004f6289ec1d35466add7770abcc185f7d1ecdf18f1ef8fb13f4f5a5c5191b2533a7c7621dfa3c08bdda85492e63cb9f2e9ae7dd1887ddda71e03a52e9e5219afa344123ac9174e25c585d6d719c97599009d891adf11ff7c66f1b04d41da76ee73b30d34fdaefbe2827c404a2e6eedf9ac357c864846fd919b43e9ff3a455f4e06d3098664c890346ddafca3a19d1fd4e2553854fdb9bbc78977e9646c382c033e3b789a8ed91b49864716c9d25d834d90fd65323d5640db544411838cececcd8c4e2616e195d595a0deb247085d5c61410102818100d11cf7f012e95298ff64fa9ce58013a086e5335bf8e5372d43701817421f1a9b04a66f358819f63dec04bc72f30d54dc7cbc87a01f47e7a9e56dafb29f5ee8cbae7340dcf8c6db030f73db01cc6938d5c2508ea5dd81aeea9e9cca77a717d5cf32e559600784ed4bb57c3f1a7ae9c2e513d4d12c93927b41dd19c29904a42a9d02818100e66a1edb3a0ff923c96be0317cd289838193b8dd2f6fb1a1860126b17f6652cd5b49e732f12c36454f18d9606af7bf61b2b492f2f021e78841fc95259035e35d4060ad5be2baa712148141532b949b71a264a675606ad22edcddcde18d34918d23db2f097a2447dca9c9ff64cdf4601510d5b3e7b8ae02135e9f45406935dd010281806f7270f19222a7d2c2ca9e86600a126bcb78fc1658605137de692f6db5dfbdde406c3378e44071ec2e8d97a1ebc77f22c397f6f06fbb72cc296a7be946e6de4b2f7e5d63677313e65da5f162d3fe803bec83e282a3bb29ee00faaf2d75f04e134f9ccc3551cc966b731df4c3b81e3db0b911032a2ebc32d4b771b334ba3484410281810091dfaf87557c155c0dc2291ecb8ab31ab9a75f4b5123e28e833b295708742c89ec789e51c714198bc9a6cec057186066a6efe174c288847fe45ed7c1ff49ce971411e0cf227ccf17083a48b4320c14595dd960f540c4802ac113ffab036dbb946295fa72828c839e7533f867c66827884eaf2d05d00b022f672168837dd8670102818078e1e73d5fa8c900fa8e1b0ce61e5353d1f200808a4756180a946fe42eb3696d6976879582f4f6ac02a53d2172168339d6324afffeee0e3f0b762020d4242d9beceee75d7b5d36a4e745754d1e2e9970ec497ea042c4ec5ca9aa1cc4f38142057d44eb4b8b860a226c5d38ba3907f7deebc53fb9b22dc3aa1a8dd96d5fbae350"

    const privateKey = crypto.createPrivateKey({
        key: privateKeyString,
        format: 'der',
        type: 'pkcs8',
        encoding: 'hex'
    });

    const publicKey = crypto.createPublicKey(privateKey).export({
        type: 'pkcs1',
        format: 'der'
    });

    const apikey = crypto.createHash('sha256').update(publicKey).digest('base64')
    const apiSignature = crypto.sign('sha256', Buffer.from(JSON.stringify(body)), {
        key: privateKey,
        type: 'pkcs8',
        format: 'der'
    });

    return JSON.stringify({
        'Content-Type': 'application/json',
        'X-Api-Key': apikey,
        'X-Api-Signature': apiSignature
    })
}

server.post("/getCurrenciesFull", async (req, res) => {
    const options = {
        'method': 'POST',
        'url': 'https://api.changelly.com/v2',
        'headers': getHeaders(req.body),
        body: JSON.stringify(req.body)
    };
    request(options, function (error, response) {
        if (error) throw new Error(error);
        console.log(response)
        res.send(response.body)
    });
})

server.post("/getExchangeAmount", async (req, res) => {
    const options = {
        'method': 'POST',
        'url': 'https://api.changelly.com/v2',
        'headers': getHeaders(req.body),
        body: JSON.stringify(req.body)
    };
    request(options, function (error, response) {
        if (error) throw new Error(error);
        console.log(response.body)
        res.send(response.body)
    });
})

server.post("/validateAddress", async (req, res) => {
    const options = {
        'method': 'POST',
        'url': 'https://api.changelly.com/v2',
        'headers': getHeaders(req.body),
        body: JSON.stringify(req.body)
    };
    request(options, function (error, response) {
        if (error) throw new Error(error);
        console.log(response.body)
        res.send(response.body)
    });
})


server.post("/createTransaction", async (req, res) => {
    const options = {
        'method': 'POST',
        'url': 'https://api.changelly.com/v2',
        'headers': getHeaders(req.body),
        body: JSON.stringify(req.body)
    };
    request(options, function (error, response) {
        if (error) throw new Error(error);
        console.log(response.body)
        res.send(response.body)
    });
})

server.post("/getStatus", async (req, res) => {
    const options = {
        'method': 'POST',
        'url': 'https://api.changelly.com/v2',
        'headers': getHeaders(req.body),
        body: JSON.stringify(req.body)
    };
    request(options, function (error, response) {
        if (error) throw new Error(error);
        console.log(response.body)
        res.send(response.body)
    });
})
