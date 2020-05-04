const crypto = require("crypto");

const AWS = require("aws-sdk");
const fs = require("fs").promises;
const util = require("util");

const s3 = new AWS.S3({
	signatureVersion: "v4",
});

const getRandomFilename = () =>	require("crypto").randomBytes(16).toString("hex");

module.exports.handler = async (event) => {
	if (event.path === "/") {
		const html = await fs.readFile(__dirname+"/index.html", "utf8");

		// does not handle pagination, only for demonstration
		const objects = await s3.listObjectsV2({Bucket: process.env.BUCKET}).promise();
		const contents = await Promise.all(objects.Contents.map(async (object) => {
			const SSES3Pattern = /^SSE-S3-[0-9a-fA-F]*$/;
			const SSEKMSdefaultPattern = /^SSE-KMS-default-[0-9a-fA-F]*$/;
			const SSEKMScustomPattern = /^SSE-KMS-custom-[0-9a-fA-F]*$/;
			const SSECPattern = /^SSE-C-(?<keyHex>.*)-[0-9a-fA-F]*$/;

			const encryptionParams = await (async () => {
				if (object.Key.match(SSES3Pattern)) {
					return {
						encryption: "SSE-S3",
						image: await s3.getSignedUrlPromise("getObject", {Bucket: process.env.BUCKET, Key: object.Key}),
					};
				} else if (object.Key.match(SSEKMSdefaultPattern)) {
					return {
						encryption: "SSE-KMS (default key)",
						image: await s3.getSignedUrlPromise("getObject", {Bucket: process.env.BUCKET, Key: object.Key}),
					};
				} else if (object.Key.match(SSEKMScustomPattern)) {
					return {
						encryption: "SSE-KMS (custom CMK)",
						image: await s3.getSignedUrlPromise("getObject", {Bucket: process.env.BUCKET, Key: object.Key}),
					};
				} else if (object.Key.match(SSECPattern)) {
					const {keyHex} = object.Key.match(SSECPattern).groups;
					const key = Buffer.from(keyHex, "hex");
					const keyMd5 = crypto.createHash("md5").update(key).digest("base64");

					const url = await s3.getSignedUrlPromise("getObject", {
						Bucket: process.env.BUCKET,
						Key: object.Key,
						SSECustomerAlgorithm: "AES256",
					});

					const headers = {
						"x-amz-server-side-encryption-customer-algorithm": "AES256",
						"x-amz-server-side-encryption-customer-key": key.toString("base64"),
						"x-amz-server-side-encryption-customer-key-MD5": keyMd5,
					};
					const id = crypto.randomBytes(16).toString("hex");

					return {
						encryption: "SSE-C",
						encryptionKey: keyHex,
						imageScript: `
<div id="id${id}"><img/></div><script>fetch("${url}", {headers: ${JSON.stringify(headers)}}).then((res) => res.blob()).then((b) => document.querySelector("#id${id} img").src = URL.createObjectURL(b))</script>
						`,
					};
				}
			})();

			return {
				key: object.Key,
				...encryptionParams,
			};
		}));

		const table = contents.length > 0 ? contents.map(({key, encryption, encryptionKey, image, imageScript}) => {
			return `
<tr>
	<td>${key}</td>
	<td>${encryption}</td>
	<td>${encryptionKey}</td>
	<td>${image ? `<img src="${image}"/>` : `${imageScript}`}</td>
</tr>
			`;
		}).join("") : "<tr><td colspan=\"5\">No images uploaded</td></tr>";

		const withContents = html.replace("$$BUCKET_CONTENTS$$", table);

		return {
			statusCode: 200,
			headers: {
				"Content-Type": "text/html",
			},
			body: withContents,
		};
	} else if (event.path === "/sign_post") {
		const {encryption} = event.queryStringParameters;
		const encryptionParams = (() => {
			if (encryption === "SSE-S3") {
				return {
					key: `SSE-S3-${getRandomFilename()}`,
					fields: {
						"x-amz-server-side-encryption": "AES256",
					},
				};
			}else if (encryption === "SSE-KMS-default") {
				return {
					key: `SSE-KMS-default-${getRandomFilename()}`,
					fields: {
						"x-amz-server-side-encryption": "aws:kms",
					},
				};
			}else if (encryption === "SSE-KMS-custom") {
				return {
					key: `SSE-KMS-custom-${getRandomFilename()}`,
					fields: {
						"x-amz-server-side-encryption": "aws:kms",
						"x-amz-server-side-encryption-aws-kms-key-id": process.env.CMK_ID,
					},
				};
			}else if (encryption === "SSE-C") {
				const key = crypto.randomBytes(32);
				const keyBase64 = key.toString("base64");
				const keyMd5 = crypto.createHash("md5").update(key).digest("base64");
				return {
					key: `SSE-C-${key.toString("hex")}-${getRandomFilename()}`,
					fields: {
						"x-amz-server-side-encryption-customer-algorithm": "AES256",
						"x-amz-server-side-encryption-customer-key": keyBase64,
						"x-amz-server-side-encryption-customer-key-MD5": keyMd5,
					},
				};
			}else {
				throw Error(`Unknown algo: ${encryption}`);
			}
		})();
		const data = await util.promisify(s3.createPresignedPost.bind(s3))({
			Bucket: process.env.BUCKET,
			Fields: {
				key: encryptionParams.key,
			},
			Conditions: [
				["content-length-range", 	0, 1000000], // content length restrictions: 0-1MB
				["starts-with", "$Content-Type", "image/"], // content type restriction
				...Object.entries(encryptionParams.fields).map(([k, v]) => ["eq", `$${k}`, v]),
			]
		});

		Object.entries(encryptionParams.fields).forEach(([k, v]) => data.fields[k] = v);
		return {
			statusCode: 200,
			headers: {
				"Content-Type": "text/json",
			},
			body: JSON.stringify(data),
		};
	}
};
