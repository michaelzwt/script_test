#conding=utf8
import requests, json

def get_value_from_list(t_list, t_target_key, t_key,t_word):
    for element in t_list:
        if element[t_key] == t_word:
            return element[t_target_key]
    return None

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
        print self.tokens

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
        self.tokens =  iam_requests.headers["X-Subject-Token"]
        return self.tokens

    def get_iam_project_tokens(self):
        project_id = self.get_project_id(self.field)
        iam_body = self.get_iam_token_body("project", project_id)
        url = "https://%s/v3/auth/tokens" % self.field_endpoint_dict[self.field]
        headers = {'Content-Type': 'application/json'}
        iam_requests = requests.post(url=url, headers=headers, data=json.dumps(iam_body))
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

class ECS_MANAGER:
    field_endpoint_dict = {"cn-north-1": "iam.cn-north-1.myhuaweicloud.com",
                           "cn-east-2": "iam.cn-east-2.myhuaweicloud.com",
                           "cn-south-1": "iam.cn-south-1.myhuaweicloud.com",
                           "cn-northeast-1": "iam.cn-northeast-1.myhuaweicloud.com",
                           "ap-southeast-1": "iam.ap-southeast-1.myhwclouds.com",
                           "ALL": "iam.myhuaweicloud.com"}
    def __init__(self):
        pass

    def create_ecs(self, project_id, field):
        url = "https://%s/v1/%s/cloudservers" % (self.field_endpoint_dict[self.field], project_id)
        
if __name__ == "__main__":
    field = "cn-north-1"
    y = IAM_MANAGER("zhuwentao", "abc123456", "hwcloudsom3", field)
    project_tokens = y.get_iam_project_tokens()
    project_id = y.get_project_id(field)
    test = PRIVATE_VPC("zhuwentao", "abc123456", "hwcloudsom3", field)
    subnet = "192.168.0.0/16"
    vpc_info =  test.create_vpc(project_id, project_tokens, "hhhhhhtest", subnet)
    print test.query_vpc(project_id, project_tokens, vpc_info["id"])
    subnet_name = "htest_subnet"
    cidr = "192.168.200.0/24"
    gateway_ip = "192.168.200.1"
    az = "cn-north-1a"
    vpc_id = vpc_info["id"]
    subnet_id =  test.create_subnet(project_id, project_tokens, subnet_name, cidr, gateway_ip, az, vpc_id)["id"]
    group_id =  test.create_security_group(project_id, project_tokens, "htest", vpc_id)["id"]