# See http://www.deplication.net/2014/09/aws-script-of-day-cascade-delete-of.html
import sys
import argparse
import boto.ec2
import boto.elasticache
import boto.rds

def get_args():
    parser = argparse.ArgumentParser(
        description='Remove all references to a security group and then delete it')
    parser.add_argument('group_ids', nargs='+', 
        help='The ID of the security group to delete, eg. sg-xxxxxxx')
    parser.add_argument('--region', default='us-east-1', 
        help='AWS region name the security group is in, default: us-east-1')
    parser.add_argument('--quick', 
        help='Skip checks for whether or not the group is used by RDS/ElastiCache. Faster but may cause error on delete if the group is referenced.', 
        action="store_true")
    parser.add_argument('--force', 
        help='Force delete without requiring confirmation', 
        action="store_true")
    parser.add_argument('--quiet', 
        help='Do not print references or success message', 
        action="store_true")
    return parser.parse_args()

def get_ec2_connection(region=None):
    return boto.ec2.connect_to_region(region)

def get_groups(connection):
    return connection.get_all_security_groups()

def check_elasticache(region, groups, names):
    cache = boto.elasticache.connect_to_region(region)
    try:
        cache_groups = cache.describe_cache_security_groups()
        for cache_group in cache_groups['DescribeCacheSecurityGroupsResponse']['DescribeCacheSecurityGroupsResult']['CacheSecurityGroups']:
            for ec2_group in cache_group['EC2SecurityGroups']:
                if ec2_group['EC2SecurityGroupName'] in names:
                     raise ValueError('Security group [%s] is used in cache security group [%s] and cannot be deleted' % 
                        (ec2_group['EC2SecurityGroupName'], cache_group['CacheSecurityGroupName']))
    except boto.exception.BotoServerError:
        # Only supported on EC2 Classic, try VPC instead
        pass
    # Check VPC
    clusters = cache.describe_cache_clusters()
    for cluster in clusters['DescribeCacheClustersResponse']['DescribeCacheClustersResult']['CacheClusters']:
        for group in cluster['SecurityGroups']:
            if group['SecurityGroupId'] in groups:
                raise ValueError('Security group [%s] is used in cache cluster [%s] and cannot be deleted' % 
                    (group['SecurityGroupId'], cluster['CacheClusterId']))

def check_rds(region, groups, names):
    rds = boto.rds.connect_to_region(region)
    # Check EC2 classic
    rds_groups = rds.get_all_dbsecurity_groups()
    for rds_group in rds_groups:
        for ec2_group in rds_group.ec2_groups:
            if ec2_group.EC2SecurityGroupId in groups:
                raise ValueError('Security group [%s] is used in RDS security group [%s] and cannot be deleted' % 
                    (ec2_group.EC2SecurityGroupId, rds_group.name))
    # Check VPC
    instances = rds.get_all_dbinstances()
    for instance in instances:
        for rds_group in instance.vpc_security_groups:
            if rds_group.vpc_group in groups:
                raise ValueError('Security group [%s] is used by RDS database [%s] and cannot be deleted' % 
                    (rds_group.vpc_group, instance.DBName))

def get_regions():
    regions = []
    for region in boto.ec2.regions():
        regions.append(str(region.name))
    return regions

def check_region(region):
    regions = get_regions()
    if region not in regions:
        raise ValueError('Invalid region name [%s], must be one of:\n\t%s.' % (region, regions))

def validate_args(args, groups):
    ids = []
    for group_id in args.group_ids:
        if not group_id.startswith('sg-'):
            raise ValueError('Invalid security group name: [%s]' % group_id)
        ids.append(group_id)
    names = []
    for group in groups:
        if group.id in ids:
            ids.remove(group.id)
            names.append(group.name)
    if len(ids) > 0:
        raise ValueError('Security group(s) %s not found in region [%s]' % (str(ids), args.region))
    if not args.quick:
        check_elasticache(args.region, args.group_ids, names)
        check_rds(args.region, args.group_ids, names)

def find_referring_rules(rules, target):
    refs = []
    for rule in rules:
        for grant in rule.grants:
            if (grant.group_id == target):
                refs.append(rule)
    return refs

def find_ec2_references(groups,target):
    ref_map = {}
    for group in groups:
        if (group.id == target):
            continue
        ingress = find_referring_rules(group.rules, target)
        egress = find_referring_rules(group.rules_egress, target)
        if len(ingress) > 0 or len(egress) > 0:
            ref_map[group] = {} 
            if len(ingress) > 0:
                ref_map[group]['ingress'] = ingress
            if len(egress) > 0:
                ref_map[group]['egress'] = egress
    return ref_map

def display_references(references, target):
    print '\nSecurity group %s is referenced by the following groups:' % target
    for key in references.keys():
        print 'EC2 security group: %s (%s)' % (key.name, key.id)
        if 'ingress' in references[key]:
            for rule in references[key]['ingress']:
                print '\tInbound protocol [%s], port range [%s-%s]' % (rule.ip_protocol, rule.from_port, rule.to_port)
        if 'egress' in references[key]:
            for rule in references[key]['egress']:
                print '\tOutbound protocol [%s], port range [%s-%s]' % (rule.ip_protocol, rule.from_port, rule.to_port)

def confirm_delete(target):
    answer = raw_input('Are you sure you want to delete security group %s? [y/n] ' % target)
    answer = answer.lower()
    return answer == 'y' or answer == 'yes'

def delete_group(connection, references, target):
    if len(references) > 0:
        for ref in references:
            if 'ingress' in references[ref]:
                for rule in references[ref]['ingress']: 
                    connection.revoke_security_group(group_id=ref.id, 
                        src_security_group_group_id=target, 
                        ip_protocol=rule.ip_protocol, 
                        from_port=rule.from_port, to_port=rule.to_port)
            if 'egress' in references[ref]:
                for rule in references[ref]['egress']: 
                    connection.revoke_security_group_egress(group_id=ref.id, 
                        src_group_id=target, 
                        ip_protocol=rule.ip_protocol, 
                        from_port=rule.from_port, to_port=rule.to_port)
    connection.delete_security_group(group_id=target)

def main():
    args = get_args()
    check_region(args.region)
    connection = get_ec2_connection(args.region)
    groups = get_groups(connection)
    validate_args(args,groups)

    for target in args.group_ids:
        references = find_ec2_references(groups, target)
        if len(references) > 0 and not args.quiet:
            display_references(references, target)
        if (args.force or confirm_delete(target)):
            if not args.quiet:
                print 'Deleting security group: %s' % target
            delete_group(connection, references, target)
        else:
            if not args.quiet:
                print 'Skipping security group: %s' % target
    if not args.quiet:
        print 'Done.'
            

if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        print str(e)
        sys.exit(2)
    except boto.exception.EC2ResponseError as b:
        print 'Delete failed with error code: [%s] and message: [%s]' % (b.error_code, b.message)
        sys.exit(3)
