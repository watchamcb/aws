import boto3
import botocore
import time

def save_config(client, bucket_name, rules):
    lifecycle = {}
    lifecycle['Rules'] = rules
    response = client.put_bucket_lifecycle_configuration(Bucket=bucket_name, LifecycleConfiguration=lifecycle)
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        print('[%s] AbortIncompleteMultipartUpload lifecycle configuration created successfully.' % (bucket_name))
    else:
        print('Failed creating lifecycle configuration on bucket [%s], response: [%s]' % (bucket_name, str(response)))

def create_default_abort_policy():
    policy = {}
    policy['ID'] = 'AbortMultipartUploads'
    policy['Prefix'] = '' 
    policy['Status'] = 'Enabled' 
    policy['AbortIncompleteMultipartUpload'] = { 'DaysAfterInitiation': 7 }
    return policy

def create_new_lifecycle(client, bucket_name):
    print('[%s] has no lifecycle configuration, creating default configuration...' % (bucket_name))
    save_config(client, bucket_name, [create_default_abort_policy()])

def rule_has_abort_policy(rule):
    return rule.has_key('AbortIncompleteMultipartUpload')

def update_prefix_rules(rules):
    # Used when at least one prefix has abort policy set, ensure all prefixes also have abort.
    update_count = 0
    for rule in rules:
        if rule['Prefix'] == '':
            continue
        if rule_has_abort_policy(rule):
            continue
        rule['AbortIncompleteMultipartUpload'] = { 'DaysAfterInitiation': 7 }
        update_count += 1
    return update_count > 0

def update_lifecycle(client, bucket_name):
    try:
        lifecycle = client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = lifecycle['Rules']
        entire_bucket_policy = None
        has_abort_policy = False
        for rule in rules:
            #Check for bucket wide multipart abort policy
            if rule['Prefix'] == '':
                entire_bucket_policy = rule
                if rule_has_abort_policy(entire_bucket_policy):
                    print('[%s] has existing AbortIncompleteMultipartUpload lifecycle configuration, skipping.' % (bucket_name))
                    return
            has_abort_policy = rule_has_abort_policy(rule)
            if has_abort_policy:
                break

        if not entire_bucket_policy and not has_abort_policy:
            # No existing bucket wide policy and no abort policy on prefixes, create default bucket wide policy, leave prefixes unchanged 
            print('[%s] has no AbortIncompleteMultipartUpload policy, creating new policy for bucket' % (bucket_name))
            rules.append(create_default_abort_policy())
            save_config(client, bucket_name, rules)
        elif entire_bucket_policy and not has_abort_policy:
            # Existing bucket wide policy with no abort policy on prefixes, update existing policy to add abort, leave prefixes unchanged
            print('[%s] adding AbortIncompleteMultipartUpload to existing policy' % (bucket_name))
            entire_bucket_policy['AbortIncompleteMultipartUpload'] = { 'DaysAfterInitiation': 7 }
            save_config(client, bucket_name, rules)
        elif has_abort_policy:
            if update_prefix_rules(rules):
                print('[%s] has AbortIncompleteMultipartUpload on prefix, updating other prefixes' % (bucket_name))
                save_config(client, bucket_name, rules)
            else:
                print('[%s] has existing AbortIncompleteMultipartUpload lifecycle prefix configuration, skipping.' % (bucket_name))
    except botocore.exceptions.ClientError as e:
        if 'NoSuchLifecycleConfiguration' == e.response['Error']['Code']:
            # No lifecycle rules on bucket
            create_new_lifecycle(client, bucket_name)
        else:
            print('Error processing bucket [%s]: [%s]' % (bucket_name, str(e)))

def main():
    s3 = boto3.resource('s3')
    client = boto3.client('s3')
    client_map = {}
    for bucket in s3.buckets.all():
        # Hack to work around SigV4 breaking in eu-central, need to create client with region so boto3 signs request correctly
        region = client.get_bucket_location(Bucket=bucket.name)['LocationConstraint']
        if region == None:
            #US Standard has no location constraint set
            region = 'us-east-1'
        if not client_map.has_key(region):
            #Cache regional clients
            client_map[region] = boto3.client('s3', region_name=region)
        client = client_map[region]

        parts = client.list_multipart_uploads(Bucket=bucket.name, MaxUploads=10)
        if parts.has_key('Uploads'):
            print('[%s] has incomplete multipart uploads and will be affected by this change.' % (bucket.name))
        else:
            # Comment out this block if you want to apply to all buckets regardless of whether or not they contain failed multipart uploads
            print('[%s] does not have incomplete multipart uploads, skipping.' % (bucket.name))
            continue
        update_lifecycle(client, bucket.name)
        # Avoid throttling, take a break
        time.sleep(2)
    print('Done!')

if __name__ == '__main__':
    main()
