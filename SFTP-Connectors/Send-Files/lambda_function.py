import json
import urllib.parse
import boto3
import gnupg
import botocore
import os
from botocore.exceptions import ClientError

# Declare global clients
s3_client = boto3.client('s3')
secretsmanager_client = boto3.client('secretsmanager')

# Function to retrieve specified secret_value from secrets manager
def get_secret_details(secretArn, pgpKeyType):
    try:
        response = secretsmanager_client.get_secret_value(SecretId=secretArn)
        # Create dictionary
        secret = response['SecretString']
        if secret:
            secret_dict = json.loads(secret)
        else:
            print("Secrets Manager exception thrown")
            return {
                "errorMessage": "Secrets Manager exception thrown"
            }
        if pgpKeyType in secret_dict:
            PGPKey = secret_dict[pgpKeyType]
        else:
            print(f"{pgpKeyType} not found in secret")
            return {
                "errorMessage": f"{pgpKeyType} not found in secret"
            }
        return {
            "PGPKey": PGPKey
        }
    except ClientError as e:
        print(json.dumps(e.response))
        return {
            'errorCode': e.response['Error']['Code'],
            'errorMessage': e.response['Error']['Message']
        }

# Function that performs PGP encryption
def encrypt_file(input_file, output_file, recipient):
    gpg = gnupg.GPG(homedir='/tmp', gpgbinary='/bin/gpg')
    # Encrypt file
    encrypted_file = gpg.encrypt_file(input_file, recipients=recipient, output=output_file)

    # If encryption fails, raise exception
    if encrypted_file.status != 0:
        raise Exception(f"Error encrypting file: {encrypted_file.stderr}")

# Function that wipes /tmp directory clean
def wipe_tmp_directory():
    for root, dirs, files in os.walk("/tmp"):
        for file in files:
            os.remove(os.path.join(root, file))

# Lambda handler
def handler(event, context):
    print(json.dumps(event))

    # Encryption requires PGP public key
    pgpKeyType = 'PGPPublicKey'

    # Get variables from event
    partnerId = event['JobParameters']['body']['partnerId']
    pgpSecret = event['JobParameters']['body']['pgpSecret']
    outputBucket = event['JobParameters']['body']['outputBucket']
    outputSubfolder = event['JobParameters']['body'].get('outputSubfolder', 'encrypted-files')  # New field for output subfolder

    if 'CustomStep' in event:
        bucket = event['CustomStep']['body']['bucket']
        key = urllib.parse.unquote_plus(event['CustomStep']['body']['key'])
    else:
        bucket = event['bucket']
        key = urllib.parse.unquote_plus(event['key'])

    # Set required file names
    file = key.split('/')[-1]
    output_file = '/tmp/' + file + '.gpg'
    encrypted_file_name = file + '.gpg'

    # Define new subfolder in the output bucket to store the encrypted file
    encrypted_key = f"{outputSubfolder}/{partnerId}/{encrypted_file_name}"  # Placing in specified subfolder

    print(f'File name: {file}')
    print(f'Output file name: {output_file}')
    print(f'Encrypted file name: {encrypted_file_name}')
    print(f'Encrypted key: {encrypted_key}')

    # Ensure /tmp directory is empty
    print('Wiping tmp directory')
    wipe_tmp_directory()

    # Get PGP key from Secrets Manager
    pgpDetails = get_secret_details(pgpSecret, pgpKeyType)
    if 'errorMessage' in pgpDetails:
        return pgpDetails  # Return error message if PGP key retrieval fails

    PGPPublicKey = pgpDetails['PGPKey']

    # Import PGP public key into keyring
    gpg = gnupg.GPG(gnupghome='/tmp', gpgbinary='/bin/gpg')
    print("GPG binary initialized successfully")
    print('Trying importing PGP public key')
    import_result = gpg.import_keys(PGPPublicKey)
    print("PGP Public Key imported successfully")

    # Download unencrypted file from S3
    try:
        downloadStatus = download_file(bucket, key, file)
        local_file_name = '/tmp/' + file

        # If file downloads successfully, continue with encryption process
        if downloadStatus:
            print("Download successful")

            # Perform PGP encryption
            status = gpg.encrypt_file(local_file_name, recipients=import_result.fingerprints, output=output_file)

            # Print encryption status information to logs
            print("ok: ", status.ok)
            print("status: ", status.status)
            print("stderr: ", status.stderr)

            # Upload encrypted file to S3 to be sent to remote SFTP server
            try:
                print(f"Uploading file: {output_file}, to bucket: {outputBucket}, as key: {encrypted_key}")
                s3response = s3_client.upload_file(output_file, outputBucket, encrypted_key)
                print("File uploaded successfully")
            except ClientError as error:
                print(error.response['Error']['Code'])
                print(error.response['Error']['Message'])
                return False

            # Create JSON body response containing encrypted file S3 path to be passed to next step in step function
            body = {
                'bucket': outputBucket,
                'key': encrypted_key,
                's3_path': ['/' + outputBucket + '/' + encrypted_key]
            }

            statusCode = 200
            response = {
                'statusCode': statusCode,
                'body': body
            }

            # Wipe /tmp directory after encryption has been completed and file has been transferred
            wipe_tmp_directory()

            # Return encrypted file name / S3 path to be passed to next step in step function
            return response

    except Exception as e:
        print(e)
        print(f'Error getting object {key} from bucket {bucket}. Make sure they exist and your bucket is in the same region as this function.')
        raise
