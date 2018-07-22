# -*- coding:UTF-8 -*-
import requests, json, random, sys

class LOGGER:
    def __init__(self):
        pass
    def info(self,str):
        print '\033[1;32m %s \033[0m!' % str
    def error(self, str):
        print '\033[1;31m %s \033[0m!' % str

def get_value_from_list(t_list, t_target_key, t_key,t_word):
    for element in t_list:
        if element[t_key] == t_word:
            return element[t_target_key]
    return None

def check_exit(result, str):
    if result is False:
        LOGGER().error(str)
        sys.exit(1)

def create_rand_str(length, sn = False):
    seed_sn = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-"
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if sn is True:
        seed_t = seed_sn
    else:
        seed_t = seed
    sa = []
    for i in range(length):
        sa.append(random.choice(seed_t))
    salt = ''.join(sa)
    return salt

class IAM_MANAGER:
    field_endpoint_dict = {"cn-north-1": "iam.cn-north-1.myhuaweicloud.com",
                           "cn-east-2": "iam.cn-east-2.myhuaweicloud.com",
                           "cn-south-1": "iam.cn-south-1.myhuaweicloud.com",
                           "cn-northeast-1": "iam.cn-northeast-1.myhuaweicloud.com",
                           "ap-southeast-1": "iam.ap-southeast-1.myhwclouds.com",
                           "ALL": "iam.myhuaweicloud.com"}
    scope_value = {"domain": "name", "project": "id"}
    def __init__(self, user_name, password, domain_name, field):
        self.user_name = user_name
        self.password = password
        self.domain_name = domain_name
        self.field = field
        self.tokens = self.get_iam_tokens()

    def get_iam_token_body(self,scope_name,value):
        iam_body = {
          "auth": {
            "identity": {
              "methods": [
                "password"
              ],
              "password": {
                "user": {
                  "name": self.user_name,
                  "password": self.password,
                  "domain": {
                    "name": self.domain_name
                  }
                }
              }
            },
            "scope": {
              scope_name: {
                self.scope_value[scope_name]: value
              }
            }
          }
        }
        return iam_body

    def get_iam_tokens(self):
        iam_body = self.get_iam_token_body("domain", self.domain_name)
        url = "https://%s/v3/auth/tokens" % self.field_endpoint_dict[self.field]
        headers = {'Content-Type': 'application/json'}
        iam_requests = requests.post(url = url, headers = headers, data = json.dumps(iam_body))
        if iam_requests.status_code != requests.codes.created:
            LOGGER().error("获取token失败，请确认账号信息是否填写正确")
            sys.exit(1)
        self.tokens =  iam_requests.headers["X-Subject-Token"]
        return self.tokens

    def get_iam_project_tokens(self):
        project_id = self.get_project_id(self.field)
        iam_body = self.get_iam_token_body("project", project_id)
        url = "https://%s/v3/auth/tokens" % self.field_endpoint_dict[self.field]
        headers = {'Content-Type': 'application/json'}
        iam_requests = requests.post(url=url, headers=headers, data=json.dumps(iam_body))
        if iam_requests.status_code != requests.codes.created:
            LOGGER().error("获取token失败，请确认账号信息是否填写正确")
            sys.exit(1)
        self.tokens = iam_requests.headers["X-Subject-Token"]
        return self.tokens

    def get_user_access_project_list(self):
        url = "https://%s/v3/auth/projects" % self.field_endpoint_dict[self.field]
        headers = {"X-Auth-Token": self.tokens}
        request_result = requests.get(url = url, headers = headers)
        return request_result.json()["projects"]

    def get_project_id(self, field):
        project_list = self.get_user_access_project_list()
        return get_value_from_list(project_list, "id", "name", field)

class PRIVATE_VPC:
    field_endpoint_dict = {"cn-north-1": "vpc.cn-north-1.myhuaweicloud.com",
                           "cn-east-2": "vpc.cn-east-2.myhuaweicloud.com",
                           "cn-south-1": "vpc.cn-south-1.myhuaweicloud.com",
                           "cn-northeast-1": "vpc.cn-northeast-1.myhuaweicloud.com",
                           "ap-southeast-1": "vpc.ap-southeast-1.myhwclouds.com"}
    def __init__(self, user_name, password, domain_name, field):
        self.user_name = user_name
        self.password = password
        self.domain_name = domain_name
        self.field = field

    def get_quota_type_list(self):
        return [ "vpc", "subnet", "securityGroup", "securityGroupRule", "publicIp", "vpn", "vpngw", "vpcPeer", "loadbalancer", "listener", "firewall", "shareBandwidth", "shareBandwidthIP"]

    def get_quota(self, project_id, tokens, type):
        url = "https://%s/v1/%s/quotas?type=%s" % (self.field_endpoint_dict[self.field], project_id, type)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query vpc failed"
            return False
        return request_result.json()["quotas"]["resources"]

    def query_quota_is_limit(self, project_id, tokens, type):
        type_resource = self.get_quota(project_id, tokens ,type)
        if type_resource is not False and (int(type_resource[0]["quota"]) - int(type_resource[0]["used"]) > 0 ):
            return True
        else:
            return False

    def create_vpc(self, project_id, tokens, vpc_name, subnet):
        url = "https://%s/v1/%s/vpcs" % (self.field_endpoint_dict[self.field], project_id)
        headers = {"X-Auth-Token": tokens}
        body = self._create_vpc_body(vpc_name, subnet)
        vpc_requests = requests.post(url=url, headers=headers, data=json.dumps(body))
        if vpc_requests.status_code != requests.codes.ok:
            print "create vpc failed"
            return False
        return vpc_requests.json()["vpc"]

    def _create_vpc_body(self, name, subnet):
        body = {
         "vpc":
             {
             "name": name,
             "cidr": subnet
             }
        }
        return body
    def query_vpc(self, project_id, tokens, vpc_id):
        url = "https://%s/v1/%s/vpcs/%s" % (self.field_endpoint_dict[self.field], project_id, vpc_id)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query vpc failed"
            return False
        return request_result.json()["vpc"]

    def _create_subnet_body(self, name, cidr, gateway_ip, primary_dns, secondary_dns, az, vpc_id):
        body = {
              "subnet":
                     {
                      "name": name,
                      "cidr": cidr,
                      "gateway_ip": gateway_ip,
                      "dhcp_enable": "true",
                      "primary_dns": primary_dns,
                      "secondary_dns": secondary_dns,
                      "dnsList": [
                          "114.114.114.114",
                          "114.114.115.115"
                      ],
                      "availability_zone":az,
                      "vpc_id": vpc_id
              }
        }
        return body

    def create_subnet(self, project_id, tokens,subnet_name, cidr, gateway_ip, az, vpc_id, primary_dns="114.114.114.114", secondary_dns="114.114.115.115"):
        url = "https://%s/v1/%s/subnets" % (self.field_endpoint_dict[self.field], project_id)
        headers = {"X-Auth-Token": tokens}
        body = self._create_subnet_body(subnet_name, cidr, gateway_ip, primary_dns, secondary_dns, az, vpc_id)
        result_requests = requests.post(url=url, headers=headers, data=json.dumps(body))
        if result_requests.status_code != requests.codes.ok:
            print "create subnet failed"
            return False
        return result_requests.json()["subnet"]

    def query_subnet(self, project_id, tokens, subnet_id):
        url = "https://%s/v1/%s/subnets/%s" % (self.field_endpoint_dict[self.field], project_id, subnet_id)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query subnet failed"
            return False
        return request_result.json()["subnet"]

    def create_security_group(self, project_id, tokens, sg_name, vpc_id):
        url = "https://%s/v1/%s/security-groups" % (self.field_endpoint_dict[self.field], project_id)
        headers = {"X-Auth-Token": tokens}
        body = self._create_security_group_body(sg_name, vpc_id)
        result_requests = requests.post(url=url, headers=headers, data=json.dumps(body))
        if result_requests.status_code != requests.codes.ok:
            print "create security group failed"
            return False
        return result_requests.json()["security_group"]

    def query_security_group(self, project_id, tokens, sg_id):
        url = "https://%s/v1/%s/security-groups/%s" % (self.field_endpoint_dict[self.field], project_id, sg_id)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query security group failed"
            return False
        return request_result.json()["security_group"]

    def query_security_group_rule_id(self, project_id, tokens, sg_id):
        sg_info = self.query_security_group(project_id, tokens, sg_id)
        security_group_rules_info = sg_info["security_group_rules"]
        sg_rule_id_list = []
        for element in security_group_rules_info:
            sg_rule_id_list.append(element["id"])
        return sg_rule_id_list

    def delete_security_group_rule(self, project_id, tokens,security_group_rule_id):
        url = "https://%s/v1/%s/security-group-rules/%s" % (self.field_endpoint_dict[self.field], project_id, security_group_rule_id)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.delete(url=url, headers=headers)
        if request_result.status_code!= requests.codes.no_content:
            return False
        return True

    def _create_security_group_body(self,name, vpc_id, des = "test"):
        body = {
            "security_group": {
                "name": name,
                "description": des,
                "vpc_id": vpc_id
            }
        }
        return body

    def create_elastic_ip(self, project_id, tokens, type, name, size, share_type):
        url = "https://%s/v1/%s/publicips" % (self.field_endpoint_dict[self.field], project_id)
        headers = {"X-Auth-Token": tokens}
        body = self._create_elastic_ip_body(type, name, size, share_type)
        result_requests = requests.post(url=url, headers=headers, data=json.dumps(body))
        if result_requests.status_code != requests.codes.ok:
            print "create lastic ip failed"
            return False
        return result_requests.json()["publicip"]

    def _create_elastic_ip_body(self, type, name, size, share_type):
        body = {
            "publicip": {
                "type": type
            },
            "bandwidth": {
                "name": name,
                "size": size,
                "share_type": share_type
            }
        }
        return body

    def create_acl_policy(self, tokens,des = "xxxx"):
        url = "https://%s/v2.0/fwaas/firewall_policies" % (self.field_endpoint_dict[self.field])
        headers = {"X-Auth-Token": tokens}
        acl_name = create_rand_str(6)
        body = self._create_acl_body(acl_name, des)
        print body
        result_requests = requests.post(url=url, headers=headers, data=json.dumps(body))
        if result_requests.status_code != requests.codes.created:
            print "create acl failed"
            return False
        return result_requests.json()

    def _create_acl_body(self, name, des):
        body = {
            "firewall_policy": {
                "name": name,
                "description": des
            }
        }
        return body

    def query_all_acl_policy(self, tokens):
        url = "https://%s/v2.0/fwaas/firewall_policies" % (self.field_endpoint_dict[self.field])
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        print request_result.json()

class ECS_MANAGER:
    field_endpoint_dict = {"cn-north-1": "iam.cn-north-1.myhuaweicloud.com",
                           "cn-east-2": "iam.cn-east-2.myhuaweicloud.com",
                           "cn-south-1": "iam.cn-south-1.myhuaweicloud.com",
                           "cn-northeast-1": "iam.cn-northeast-1.myhuaweicloud.com",
                           "ap-southeast-1": "iam.ap-southeast-1.myhwclouds.com",
                           "ALL": "iam.myhuaweicloud.com"}
    def __init__(self, field):
        self.field = field

    def create_ecs(self, project_id, tokens, az, image_name, vpc_id, security_id, subnet_id):
        url = "https://%s/v1/%s/cloudservers" % (self.field_endpoint_dict[self.field], project_id)
        headers = {"X-Auth-Token": tokens}
        server_name = create_rand_str(10)
        adminPass = create_rand_str(8,True)
        imageRef = self.get_image_id(tokens, image_name)
        body = self._create_ecs_body(az, server_name, imageRef, vpc_id, security_id, subnet_id, adminPass)
        result_requests = requests.post(url=url, headers=headers, data=json.dumps(body))
        if result_requests.status_code != requests.codes.ok:
            print "create lastic ip failed"
            return False
        return result_requests.json()

    def query_job_id_status(self, project_id, tokens, job_id):
        url = "https://%s/v1/%s/jobs/%s" % (self.field_endpoint_dict[self.field], project_id, job_id)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query job_id failed"
            return False
        return request_result.json()["status"]

    def _create_ecs_body(self, az, server_name, imageRef, vpcid, security_id, subnet_id, adminPass):
        body = {
            "server": {
                "availability_zone": az,
                "name": server_name,
                "imageRef": imageRef,
                "root_volume": {
                    "volumetype": "SATA"
                },
                "flavorRef": "s2.small.1",
                "vpcid": vpcid,
                "security_groups": [
                    {
                        "id": security_id
                    }
                ],
                "nics": [
                    {
                        "subnet_id": subnet_id
                    }
                ],
                "adminPass": adminPass,
                "count": 1,
                "extendparam": {
                    "chargingMode": 0,
                }
            }
        }
        return body

    def get_private_imageRef_list(self, tokens, project_id):
        url = "https://%s/v2/images?owner=%s" % (self.field_endpoint_dict[self.field], project_id)
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query private_imageRef_list failed"
            return False
        return request_result.json()["images"]

    def get_all_imageRef_list(self, tokens):
        url = "https://%s/v2/cloudimages" % (self.field_endpoint_dict[self.field])
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query all_imageRef_list failed"
            return False
        return request_result.json()["images"]

    def get_used_share_image_list(self, tokens):
        url = "https://%s/v2/images?member_status=accepted&visibility=shared&__imagetype=shared" % (self.field_endpoint_dict[self.field])
        headers = {"X-Auth-Token": tokens}
        request_result = requests.get(url=url, headers=headers)
        if request_result.status_code != requests.codes.ok:
            print "query share imageRef_list failed"
            return False
        return request_result.json()["images"]

    def get_image_id(self, tokens, image_name):
        image_list = self.get_all_imageRef_list(tokens)
        for element in image_list:
            if element["name"] == image_name:
                return element["id"]
        return False

class USER_CASE_INFO:
    security_factor_list = ["all_delete", "part_delete", "not_delete"]
    acl_factor_list = [True, False]
    dns_factor_list = [True, False]
    gate_factor_list = [True, False]
    az_dict =   {"cn-north-1": ["cn-north-1a", "cn-north-1b"] ,
                 "cn-east-2": ["cn-north-2a", "cn-north-2b", "cn-north-2c"],
                 "cn-south-1": ["cn-south-1a", "cn-south-2b", "cn-south-1c"],
                 "cn-northeast-1": ["az1.cnnortheast1"],
                 "ap-southeast-1": ["ap-southeast-1a", "	ap-southeast-1b"]}
    az_num_value = {1: "cn-north-1", 2: "cn-east-2", 3: "cn-south-1", 4: "cn-northeast-1", 5: "ap-southeast-1"}
    image_list = [["remote_connect_windows_fault1", "remote_connect_windows_fault2", "remote_connect_windows_fault3"],
                  ["remote_connect_linux_fault1","remote_connect_linux_fault2","remote_connect_linux_fault2"]]
    def __init__(self):
        # self.input_user_info("请输入登陆方式：1：账号登陆； 2：IAM用户登录", int)
        # 1: "account_login"  2: "IAM_user_login"
        self.login_type = self.input_user_info("请输入登陆方式[1：账号登陆； 2：IAM用户登录]:", ["1", "2"])
        self.login_type = int(self.login_type)
        if self.login_type == 1:
            self.account_name = self.input_user_info("请输入账号名:", [])
            self.passwd = self.input_user_info("请输入登陆密码:", [])
        elif self.login_type == 2:
            self.account_name = self.input_user_info("请输入账号名:", [])
            self.user_name = self.input_user_info("请输入用户名:", [])
            self.passwd = self.input_user_info("请输入登陆密码:", [])
        else:
            check_exit(False, "登陆方式错误")
        self.show_case()
        self.image_key = int(self.input_user_info("", ["0","1", "2", "3", "4", "5"]))
        self.iamge_name = random.choice(self.image_list[self.image_key])
        self.security_factor = random.choice(self.security_factor_list)
        self.acl_factor = random.choice(self.acl_factor_list)
        self.dns_factor = random.choice(self.dns_factor_list)
        self.gate_factor = random.choice(self.gate_factor_list)
        az_hint = "可选择区域".center(87, "-") + "\n| " + "1: 东北-北京1     2：东北-大连     3：东北-上海二        4：华南-广州     5：亚太-香港".ljust(100, " ") + " |\n" + "-"*80 + "\n请输入创建云主机的区域："
        self.area_name =  self.az_num_value[int(self.input_user_info(az_hint, ["1", "2", "3", "4", "5"]))]
        self.az_name = random.choice(self.az_dict[self.area_name])

    def get_fault_factor_list(self):
        return {"image_key": self.image_key, "image_name": self.iamge_name, "security": self.security_factor, "acl": self.acl_factor, "dns": self.dns_factor,"gate": self.gate_factor, "az_name": self.area_name, "az": self.az_name}

    def input_user_info(self, hint, result_list):
        if len(hint) > 0:
            print hint,
        temp = raw_input()
        if len(result_list) > 0 :
            if temp.strip() not in result_list:
                check_exit(False, "输入信息类型错误，请重试")
        return temp.strip()

    def show_user_info(self):
        if self.login_type == 1:
            LOGGER().info("账号名：%s" % self.account_name)
        else:
            LOGGER().info("账号名：%s   用户名：%s" % (self.account_name, self.user_name))

    def show_case(self):
        print("故障场景".center(111, "-"))
        print("| " + "0:无法远程连接windows   1:无法远程连接linux   2:弹性ip无法ping通   3:无法访问外网    4:无法访问自建网站  5:端口不通".ljust(100, " ") + " |")
        # print("| " + "2:弹性ip无法ping通         3:无法访问外网".ljust(56, " ") + " |")
        # print("| " + "4:无法访问自建网站          5:端口不通".ljust(58, " ") + " |")
        print("-"*106)
        print("请选择要构造的场景："),

def resource_check():
    print("开始进行资源检测".center(50,"-"))
    print("开始进行检测网络资源")


if __name__ == "__main__":
    user_info = USER_CASE_INFO()
    print user_info.get_fault_factor_list()
    iam_info = IAM_MANAGER(user_info.user_name, user_info.passwd, user_info.account_name, user_info.area_name)
    project_tokens = iam_info.get_iam_project_tokens()
    project_id = iam_info.get_project_id(user_info.area_name)
    vpc_handle = PRIVATE_VPC(user_info.user_name, user_info.passwd, user_info.account_name, user_info.area_name)
    ecs_handle = ECS_MANAGER(user_info.area_name)
    # test = PRIVATE_VPC("zhuwentao", "abc123456", "hwcloudsom3", field)
    # print test.create_acl_policy(project_tokens)
    # test.query_all_acl_policy(project_tokens)

    # subnet = "192.168.0.0/16"
    # vpc_info =  test.create_vpc(project_id, project_tokens, "hhhhhhtest", subnet)
    # print test.query_vpc(project_id, project_tokens, vpc_info["id"])
    # subnet_name = "htest_subnet"
    # cidr = "192.168.240.0/24"
    # gateway_ip = "192.168.240.1"
    # az = "cn-north-1a"
    # vpc_id = vpc_info["id"]
    # subnet_id =  test.create_subnet(project_id, project_tokens, subnet_name, cidr, gateway_ip, az, vpc_id)["id"]
    # print subnet_id
    # security_group_id =  test.create_security_group(project_id, project_tokens, "htest", vpc_id)["id"]
    # print security_group_id
    # # test.query_security_group(project_id, project_tokens, security_group_id)
    # element_list = test.query_security_group_rule_id(project_id, project_tokens, security_group_id)
    # print element_list

    # for element in element_list:
    #     test.delete_security_group_rule(project_id, project_tokens, element)
    # image_name = "windows_remote_login_fault1"
    # print "begin create ecs"
    # ecs_m = ECS_MANAGER(field)
    # response = ecs_m.create_ecs(project_id, project_tokens, az, image_name, vpc_id, security_group_id, subnet_id)
    # print response