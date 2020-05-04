# Demo code to show how to use signed URLs to upload/download encrypted objects

This project shows the 4 different types of S3 encryptions:

* SSE-S3
* SSE-KMS with default key
* SSE-KMS with customer-managed CMK
* SSE-C

It provides example code how to upload files using each of these encryption schemes and how to download them from the bucket.

## How to use

### Prerequisites

* terraform

### Deploy

* ```terraform init```
* ```terraform apply```
* go to the resulting URL

### Usage

There are 4 file inputs where you can upload an image file. Each input uses a different encryption using presigned POST requests.

There is a list of object uploaded to the bucket, each showing the encryption it's using and shows the image itself.

### Destroy

* ```terraform destroy```
