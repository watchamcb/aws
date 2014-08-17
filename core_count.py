import boto.ec2 as ec2
from boto.exception import EC2ResponseError

def map_instances(reservations):
    instances = {}
    for reservation in reservations:
        for instance in reservation.instances:
            instance_type = instance.instance_type
            if instance_type not in instances:
                instances[instance_type] = 1
            else:
                instances[instance_type] = instances[instance_type] + 1
    return instances

def get_instance_map():
    instance_map = {}
    filter_dict = {'instance-state-name': 'running'}
    for region in ec2.regions():
        try:
            connection = ec2.connect_to_region(region.name)
            reservations = connection.get_all_reservations(filters=filter_dict, max_results=1000)
            instances = map_instances(reservations)
            if len(instances) > 0:
                instance_map[region.name] = map_instances(reservations)
        except EC2ResponseError:
            print("Error connecting to region %s, skipping" % region.name)
    return instance_map

def type_to_core_count(instance_type):
    large_exceptions = ['t2.medium','m2.xlarge','c1.medium']
    if instance_type in large_exceptions:
        return 2
    xl_exceptions = ['m2.2xlarge']
    if instance_type in xl_exceptions:
        return 4
    xl2_exceptions = ['m2.4xlarge','c1.xlarge']
    if instance_type in xl2_exceptions:
        return 8
    xl4_exceptions = ['hs1.8xlarge']
    if instance_type in xl4_exceptions:
        return 16

    # Everything else is pretty standard, exceptions need to be checked first
    if instance_type.endswith('.micro'):
        return 1
    if instance_type.endswith('.small'):
        return 1
    if instance_type.endswith('.medium'):
        return 1
    if instance_type.endswith('.large'):
        return 2
    if instance_type.endswith('xlarge'):
        return 4
    if instance_type.endswith('2xlarge'):
        return 8
    if instance_type.endswith('.4xlarge'):
        return 16
    if instance_type.endswith('.8xlarge'):
        return 32

    print('Unknown instance type %s, ignoring' % instance_type)
    return 0

def display_summary(instance_map):
    grand_total = 0
    for region in instance_map:
        instances = instance_map[region]
        print('Region %s' % region)
        for instance in instances:
            count = instances[instance]
            cores = count * type_to_core_count(instance)
            print('%s %s total cores: %s' % (count, instance, cores))
            grand_total += cores
    print('Grand total cores: %s' % grand_total)

def main():
    instance_map = get_instance_map()
    display_summary(instance_map)

if __name__ == "__main__":
    main()
