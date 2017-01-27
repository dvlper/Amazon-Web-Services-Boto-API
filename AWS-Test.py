'''
AWS-Test implements all the methods to test the AWS-connector
'''

__author__="dvlper"

import AWS
import sys

class TestAWS():
    '''
    TestAWS providesfunctionality to test all functionality available in vimconn-aws.py
    Functionality available:
        - get_regions_list()            - get list of regions in AWS
        - create_vpc()                  - create a VPC equivalent to tenant in OpenStack
        - get_vpc_list()                - get a list of all VPCs
        - create_subnet()               - create a subnet equivalent to network in OpenStack
        - get_all_subnet_status()       - get status of all subnets
        - create_instance()             - create a new instance/VM
        - get_all_instance_status()     - get status of all instances/VM
        - apply_action_on_instance()    - apply an action on an instance/VM
        - delete_instance()             - delete an instance/VM
        - get_instance_list()           - get a list of all instances
        - delete_subnet()               - delete a subnet
        - get_subnet_list()             - get list of all subnets
    '''
    def __init__(self, conn):
        self.conn = conn
        
    def get_region_list(self, region='us-west-2'):
        '''
        Params:
            region - name of the region
        Returns:
            region list
        '''
        return self.conn.get_region_list()

    def create_vpc(self, cidr_block, tenancy='default'):
        '''
        Params:
            cidr_block - CIDR block for the new VPC
            tenancy - type of tenancy for the instance
        Returns:
            object of the new VPC
        '''
        return self.conn.new_tenant(cidr_block, tenancy)

    def get_vpc_list(self, filter_dict={}):
        '''
        Params:
            filter_dict - a dictionary containing all the filters/options to get a list of VPCs
        Returns:
            VPCs list
        '''
        if filter_dict:
            return self.conn.get_tenant_list(filter_dict)
        else:
            return "No region mentioned in filter_dict"

    def create_subnet(self, vpc_id, cidr_block={}):
        '''
        Params:
            vpc_id - ID of the VPC in which you want to create the subnet 
            cidr_block - CIDR block for the subnet
        Returns:
            a subnet object
        '''
        if cidr_block:
            return self.conn.new_network(net_name=vpc_id, ip_profile=cidr_block)
        else:
            return "CIDR-block required"

    def get_all_subnet_status(self):
        '''
        Returns:
            astatus of all subnets
        '''
        network_list = self.conn.get_network_list()
        network_ids = map(lambda x: str(x.id), network_list)
        network_status = self.conn.refresh_nets_status(network_ids)
        return network_status

    def create_instance(self, key_name, image_id, flavor_id, net_list):
        '''
        Params:
            key_name - name of key-pair to assosiate with this instance
            image_id - iamge ID to use to create this instance
            flavor_id - flavor ID to use for creating this instance
            net_list - a list of dictionries containing following items
                net_id - subnet ID to assosiate with this instance
                elastic_ip - elastic IP to assign this instance
                security_group - security group specified by the user for this instance
        Returns:
            an object of AWS instance
        '''
        return self.conn.new_vminstance(name='Test', image_id='ami-b7a114d7', flavor_id='t2.micro', net_list=net_list)

    def get_all_instance_status(self):
        '''
        Returns:
            a list containing status of all the VM/instances 
        '''
        reservation_list = self.conn.get_vminstance_list()
        instance_ids = []
        for reservation in reservation_list:
            instance_ids.append(reservation.instances[0].id)
        instance_status = self.conn.refresh_vms_status(instance_ids)
        return instance_status

    def apply_action_on_instance(self, instance_id, action=None):
        '''
        Params:
            instance_id - ID of the instance to apply action on
            action - a string containing name of action to be applied 
        Returns:
            instance_id - ID of instance under consideration
        '''
        self.conn.action_vminstance(instance_id, action)
        return instance_id

    def delete_instance(self, instance_id):
        '''
        Params:
            instance_id - ID of the instance to delete
        Returns:
            instance_id - ID of instance under consideration
        '''
        self.conn.delete_vminstance(instance_id)
        return instance_id

    def get_instance_list(self):
        '''
        Returns:
            instance_ids - list containing IDs of all the instances
        '''
        reservation_list = self.conn.get_vminstance_list()
        instance_ids = []
        for reservation in reservation_list:
            instance_ids.append(reservation.instances[0].id)
        return instance_ids

    def delete_subnet(self, subnet_id):
        '''
        Params:
            subnet_id - ID of the subnet to delete
        Returns:
            deletes the subnet with specified subnet_id
        '''
        self.conn.delete_network(subnet_id)

    def get_subnet_list(self):
        '''
        Returns:
            a list containing subnets
        '''
        return self.conn.get_network_list()

if __name__ == '__main__':

    '''
    Testing done below tests all the functions implmented in 'vimconn-aws.py'. All 
    functions are tested in the same script. In case, you want to test anything in 
    specific, you'll have to modify the code and comment out any part of the script 
    you don't want to test.  
    '''

    # CREATING VIMCONN OBJECT
    conn = AWS.vimconnector(uuid=None, name=None, tenant_id=None, tenant_name=None, url=None, url_admin=None, user=sys.argv[1],
        passwd=sys.argv[2], log_level=None, config={})
    conn.__setitem__(index='region', value='us-west-2')

    # CREATING TEST CLASS OBJECT
    test = TestAWS(conn)

    # GETTING AWS REGION LIST
    print "\nLIST OF REGIONS\n", test.get_region_list()
    
    # CREATING VPC
    vpc_id = test.create_vpc('172.31.0.0/16', 'default')

    # GETTING VPCs LIST
    print "\nLIST OF VPCS\n", test.get_vpc_list(filter_dict={'region':'us-west-2'})
    
    # GETTING ALL SUBNETs STATUS
    subnet_status = test.get_all_subnet_status()
    print "\nSUBNETS STATUS\n", subnet_status
    
    # CREATING SUBNET
    subnet_id = test.create_subnet(vpc_id, {'cidr_block':'172.31.0.0/20'})
    
    # CREATING INSTANCE
    instance_id = test.create_instance(key_name='Test', image_id='ami-b7a114d7', flavor_id='t2.micro', 
        net_list=[{'net_id':'subnet-584c873f', 'elastic_ip':False, 'security_group':'sg-a5ca07dd'}])
    
    # GETTING ALL VMs/INSTANCEs STATUS
    print "\nINSTANCES STATUS\n", test.get_all_instance_status()
    
    # REFRESH VM/INSTANCE LIST
    print "\nLIST OF INSTANCES\n", test.get_instance_list()
    
    # REBOOTING VM/INSTANCE
    test.apply_action_on_instance(instance_id, 'reboot')
    
    # DELETING VM/INSTANCE
    test.delete_instance(instance_id)
    
    # DELETE SUBNET
    test.delete_subnet(subnet_id)
    
    # REFRESH SUBNET LIST
    test.get_subnet_list()