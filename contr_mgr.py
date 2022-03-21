#!/usr/bin/env python3

import gitlab
import yaml
import typer
import requests
import secrets
import logging
import sys
import urllib3
from gitlab.v4.objects.projects import Project as GitlabProject

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


CONTEXT_SETTINGS = dict(help_option_names=["-h", "--help"])
CONFIG_FILE = 'config.yaml'


def init_logger(debug: bool):
    logger = logging.getLogger('main')
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(logging.Formatter('%(asctime)s - %(name)s: %(message)s'))
    logger.addHandler(sh)
    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


def load_config_file(path: str):
    with open(path) as stream:
        config = yaml.safe_load(stream)
        return config


class GitLabWrapper:
    logger_name = 'main.GitLabWrapper'
    values_yaml_path = 'helm/values.yaml'
    chart_yaml_path = 'helm/Chart.yaml'

    def __init__(self, url: str, token: str, root_group_name: str, argocd_prj_name: str, prod_ref: str, stg_ref: str):
        self.logger = logging.getLogger(self.logger_name)
        self.gl = gitlab.Gitlab(url=url, private_token=token)
        self.logger.debug(f'auth in {url}')
        self.gl.auth()
        self.prod_ref = prod_ref
        self.stg_ref = stg_ref
        self.root_group = self.gl.groups.get(root_group_name)
        self.argocd_prj = self._get_gl_project(argocd_prj_name)

    def _create_project(self, name: str):
        self.logger.debug(f'Create gitlab project "{name}"')
        new_project = self.gl.projects.create({'name': name,
                                               'namespace_id': self.root_group.id})
        return new_project

    def _get_gl_project(self, name: str):
        self.logger.debug(f'Get gitlab project "{name}"')
        project_name = f'{self.root_group.name}/{name}'
        resp = self.gl.projects.get(project_name)
        return resp

    def _get_all_filenames(self, project: GitlabProject, path: str = None):
        self.logger.debug(f'Get all files from "{project.name}", path: "{path}"')
        filenames = []
        for i in project.repository_tree(path):
            if i['type'] == 'tree':
                filenames.extend(self._get_all_filenames(project, path=i['path']))
            else:
                filenames.append(i['path'])
        return filenames

    def _copy_files_(self, s_project: GitlabProject, d_project: GitlabProject):
        self.logger.debug(f'Copy files from "{s_project.name}" to "{d_project.name}"')
        filenames = self._get_all_filenames(s_project)
        for filename in filenames:
            gl_file = s_project.files.get(filename, self.prod_ref)
            _ = d_project.files.create({'file_path': filename,
                                        'branch': self.prod_ref,
                                        'content': gl_file.decode().decode(),
                                        'commit_message': f'Upload {filename}'})

    def _add_developers_to_project(self, project: GitlabProject, usernames: list):
        for username in usernames:
            self.logger.debug(f'Add {username} to {project.name}')
            resp = self.gl.users.list(search=username)
            user = resp[0]
            member = project.members.create({'user_id': user.id,
                                             'access_level': gitlab.const.DEVELOPER_ACCESS})

    def _is_user_exist(self, username: str):
        resp = self.gl.users.list(search=username)
        if resp:
            return True
        return False

    def _remove_project(self, project: GitlabProject):
        self.logger.info(f'Remove "{project.path_with_namespace}"')
        project.delete()

    def _get_yaml_content(self, project: GitlabProject, path: str, ref: str):
        self.logger.debug(f'Get yaml content "{path}", "{project.name}"')
        f = project.files.get(file_path=path, ref=ref)
        file_yaml = yaml.safe_load(f.decode())
        return file_yaml

    def _create_yaml_file(self, project: GitlabProject, path: str, data: dict, ref: str):
        self.logger.debug(f'create file: "{path}" in "{project.name}", ref "{ref}"')
        file_content = yaml.safe_dump(data)
        project.files.create({'file_path': path,
                              'branch': ref,
                              'content': file_content,
                              'commit_message': f'Create {path}'})


    def _update_yaml(self, project: GitlabProject, path: str, data: dict, ref: str):
        self.logger.debug(f'Update {path} in "{project.name}", ref: "{ref}"')
        f = project.files.get(file_path=path, ref=ref)
        file_yaml = yaml.safe_load(f.decode())
        file_yaml.update(data)
        f.content = yaml.safe_dump(file_yaml)
        f.save(branch=ref, commit_message=f'Update {path}')

    def _create_stg_env(self, project: GitlabProject, stg_env_name: str):
        self.logger.debug(f'Create env "{stg_env_name}" in "{project.name}" ')
        self._create_stg_branch(project)
        #ToDo move i3aUrl to config file
        values_yaml = {'environment': stg_env_name,
                       'i3aUrl': 'http://i3a-stg:80/'}
        self._update_yaml(project, self.values_yaml_path, data=values_yaml, ref=self.stg_ref)

    def _create_stg_branch(self, project):
        branch = self.stg_ref
        ref = self.prod_ref
        self.logger.debug(f'Create branch "{branch}" from ref: "{ref}" in "{project.name}"')
        resp = project.branches.create({'branch': branch, 'ref': ref})

    def _create_tag(self, project, tag_name: str = 'v0.0.1'):
        ref = self.prod_ref
        self.logger.debug(f'Create tag "{tag_name}" in "{project.name}", ref: {ref}')
        project.tags.create({'tag_name': tag_name, 'ref': ref})

    def _create_argocd_repo_yaml(self, name: str, file_name: str, git_repo_url: str, template_path: str):
        file_path = f'{name}/{file_name}'
        self.logger.debug(f'Create argocd repo yaml {file_path}')
        repo_yaml = self._get_yaml_content(project=self.argocd_prj, path=template_path, ref=self.prod_ref)
        repo_yaml['metadata']['name'] = name
        repo_yaml['stringData']['url'] = git_repo_url
        self._create_yaml_file(project=self.argocd_prj,
                               path=file_path,
                               data=repo_yaml,
                               ref=self.prod_ref)

    def _create_argocd_app_yaml(self, name: str, file_name: str, k8s_ns_name: str, git_repo_url: str,
                           template_path: str, env_name: str, ref: str):
        file_path = f'{name}/{file_name}'
        self.logger.debug(f'Create argocd app yaml {file_path}')
        app_yaml = self._get_yaml_content(project=self.argocd_prj, path=template_path, ref=self.prod_ref)
        app_yaml['metadata']['name'] = f'{name}-{env_name}'
        app_yaml['spec']['destination']['namespace'] = k8s_ns_name
        app_yaml['spec']['source']['repoURL'] = git_repo_url
        app_yaml['spec']['source']['targetRevision'] = ref
        self._create_yaml_file(project=self.argocd_prj,
                               path=file_path,
                               data=app_yaml,
                               ref=self.prod_ref)

    def create_argocd_app(self, name: str, git_repo_url: str, k8s_ns_prod_name: str, k8s_ns_stg_name: str,
                          argocd_repo_template: str, argocd_app_template: str, prod_env_name: str, stg_env_name: str):
        self.logger.debug(f'Create argocd app {name}')
        self.logger.debug(f'argocd_repo_template: {argocd_repo_template}, argocd_app_template: {argocd_app_template}')
        self.logger.debug(f'k8s_ns_stg_name: {k8s_ns_stg_name}, k8s_ns_prod_name: {k8s_ns_prod_name}')
        self._create_argocd_repo_yaml(name=name, file_name='repository.yaml', git_repo_url=git_repo_url,
                                      template_path=argocd_repo_template)
        self._create_argocd_app_yaml(name=name, env_name=prod_env_name, file_name=f'application-{prod_env_name}.yaml',
                                     k8s_ns_name=k8s_ns_prod_name, git_repo_url=git_repo_url,
                                     template_path=argocd_app_template, ref=self.prod_ref)
        self._create_argocd_app_yaml(name=name, env_name=stg_env_name, file_name=f'application-{stg_env_name}.yaml',
                                     k8s_ns_name=k8s_ns_stg_name, git_repo_url=git_repo_url,
                                     template_path=argocd_app_template, ref=self.stg_ref)

    def create_contract_repo(self, name: str, developers: list, owner: str, stg_env_name: str, gitlab_ci_path: str,
                             template_name: str):
        self.logger.debug(f'Create "{name}", developers: \"{", ".join(developers)}\", owner: "{owner}"')

        template_prj = self._get_gl_project(template_name)

        if not all(self._is_user_exist(d) for d in developers):
            raise ValueError(f'Users with name "{[d for d in developers if not self._is_user_exist(d)]}" not found')

        new_project = self._create_project(name=name)
        new_project.ci_config_path = gitlab_ci_path
        new_project.save()
        self._copy_files_(s_project=template_prj,
                          d_project=new_project)
        self._add_developers_to_project(project=new_project, usernames=developers)

        chart_yaml = {'name': name.replace('.', '-')}
        self._update_yaml(new_project, self.chart_yaml_path, data=chart_yaml, ref=self.prod_ref)

        values_yaml = {'owner': owner,
                       'contractName': name}
        self._update_yaml(new_project, self.values_yaml_path, data=values_yaml, ref=self.prod_ref)

        self._create_stg_env(new_project, stg_env_name)
        self._create_tag(new_project)
        return new_project

    def remove_contract_repo(self, name: str):
        project = self._get_gl_project(name=name)
        self._remove_project(project)

    def remove_argocd_app(self, name: str):
        self.logger.info(f'Remove argocd app dir {name}')
        for filename in self._get_all_filenames(self.argocd_prj, name):
            self.argocd_prj.files.delete(file_path=filename, commit_message=f'Delete {filename}', branch=self.prod_ref)



class RabbitMQClient:
    logger_name = 'main.RabbitMQWrapper'
    user_permissions = {'configure': '.*',
                        'write': '.*',
                        'read': '.*'}

    def __init__(self, url: str, admin_username: str, admin_password: str):
        self.logger = logging.getLogger(self.logger_name)
        self.url = url
        self.auth = (admin_username, admin_password)

    def create_user(self, username: str, password: str, vhost: str):
        self.logger.info(f'create rabbitmq user : "{username}" in "{self.url}"')
        user_url = f'{self.url}/api/users/{username}'
        new_user_request = {'password': password,
                            'tags': 'monitoring'}
        resp = requests.put(url=user_url,
                            auth=self.auth,
                            json=new_user_request)
        self.logger.debug(f'create rabbitmq user resp: {resp}')
        permissions_request = self.user_permissions
        permissions_url = f'{self.url}/api/permissions/{vhost}/{username}'
        resp = requests.put(url=permissions_url,
                            auth=self.auth,
                            json=permissions_request)
        self.logger.debug(f'add permissions to rabbitmq user resp: {resp}')

    def delete_user(self, username: str):
        self.logger.info(f'Remove rabbitmq user "{username}" from "{self.url}"')
        user_url = f'{self.url}/api/users/{username}'
        resp = requests.delete(url=user_url, auth=self.auth)
        self.logger.debug(f'resp: {resp}')


class VaultClient:
    logger_name = 'main.VaultClient'

    def __init__(self, url: str, token: str, verify: bool = False):
        self.logger = logging.getLogger(self.logger_name)
        self.url = url
        self.token = token
        self.headers = {'X-Vault-Token': token}
        self.verify = verify

    def read_secret(self, path: str) -> dict:
        url = f'{self.url}/v1/{path}'
        self.logger.debug(f'Read secret: "{url}"')
        resp = requests.get(url=url,
                            headers=self.headers,
                            verify=self.verify)
        resp.raise_for_status()
        return resp.json()

    def write_secret(self, path: str, data: dict):
        url = f'{self.url}/v1/{path}'
        self.logger.debug(f'Write secret: "{url}"')
        headers = self.headers.copy()
        headers.update({'Content-Type': 'application/json'})
        resp = requests.post(url=url,
                             headers=headers,
                             json=data,
                             verify=self.verify)
        self.logger.debug(f'resp: {resp}')
        resp.raise_for_status()

    def delete_secret(self, path: str):
        url = f'{self.url}/v1/{path}'
        self.logger.debug(f'Delete secret: "{url}"')
        resp = requests.delete(url=url,
                               headers=self.headers,
                               verify=self.verify)
        self.logger.debug(f'resp: {resp}')
        resp.raise_for_status()


# CLI
app = typer.Typer(add_completion=False, context_settings=CONTEXT_SETTINGS)


@app.command(context_settings=CONTEXT_SETTINGS)
def delete(contract_name: str,
           owner: str,
           tenant_prod: str,
           tenant_std: str,
           debug: bool = True,
           config_file: str = CONFIG_FILE):
    """
    Delete contract
    """
    init_logger(debug=debug)
    logger = logging.getLogger('main.delete')

    logger.info(f'name: {contract_name}')
    logger.info(f'owner: {owner}')
    logger.info(f'tenant_prod: {tenant_prod}')
    logger.info(f'tenant_std: {tenant_std}')
    app_config = load_config_file(config_file)

    # RabbitMQ
    rmq_stg_conf = app_config['rabbitmq']['stg']
    rmq_prd_conf = app_config['rabbitmq']['prd']
    rmq_stg = RabbitMQClient(url=rmq_stg_conf['url'],
                             admin_username=rmq_stg_conf['username'],
                             admin_password=rmq_stg_conf['password'])
    rmq_prod = RabbitMQClient(url=rmq_prd_conf['url'],
                              admin_username=rmq_prd_conf['username'],
                              admin_password=rmq_prd_conf['password'])
    rmq_stg.delete_user(username=contract_name)
    rmq_prod.delete_user(username=contract_name)

    # Vault
    vlt_conf = app_config['Vault']
    vc = VaultClient(url=vlt_conf['url'],
                     token=vlt_conf['token'])

    vault_path = vlt_conf['secretPath'].format(owner_name=owner,
                                               contract_name=contract_name,
                                               env=app_config['prodEnvName'])
    vc.delete_secret(vault_path)

    vault_path = vlt_conf['secretPath'].format(owner_name=owner,
                                               contract_name=contract_name,
                                               env=app_config['stgEnvName'])
    vc.delete_secret(vault_path)

    # GitLab
    gl_conf = app_config['gitlab']
    gl = GitLabWrapper(url=gl_conf['url'],
                       token=gl_conf['token'],
                       root_group_name=gl_conf['rootGroup'],
                       argocd_prj_name=gl_conf['argocdPrj'],
                       prod_ref=gl_conf['prodRef'],
                       stg_ref=gl_conf['stgRef'])

    try:
        gl.remove_contract_repo(name=contract_name)
    except Exception as e:
        logger.exception(e)
    else:
        logger.info('Success')
    gl.remove_argocd_app(contract_name)


@app.command(context_settings=CONTEXT_SETTINGS)
def create(contract_name: str,
           owner: str,
           tenant_prod: str,
           tenant_std: str,
           developers: str = None,
           debug: bool = True,
           config_file: str = CONFIG_FILE):
    """
    Create contract
    """
    init_logger(debug=debug)
    logger = logging.getLogger('main.create')

    if developers:
        developers = developers.split(',')
    else:
        developers = []

    logger.info(f'contract_name: {contract_name}')
    logger.info(f'owner: {owner}')
    logger.info(f'developers: {developers}')
    logger.info(f'tenant_std: {tenant_std}')
    logger.info(f'tenant_prod: {tenant_prod}')
    app_config = load_config_file(config_file)

    # RabbitMQ
    rmq_stg_user_password = secrets.token_urlsafe(32)
    rmq_prd_user_password = secrets.token_urlsafe(32)

    rmq_stg_conf = app_config['rabbitmq']['stg']
    rmq_prd_conf = app_config['rabbitmq']['prd']

    rmq_stg = RabbitMQClient(url=rmq_stg_conf['url'],
                             admin_username=rmq_stg_conf['username'],
                             admin_password=rmq_stg_conf['password'])
    rmq_prod = RabbitMQClient(url=rmq_prd_conf['url'],
                              admin_username=rmq_prd_conf['username'],
                              admin_password=rmq_prd_conf['password'])
    rmq_stg.create_user(username=contract_name,
                        password=rmq_stg_user_password,
                        vhost=rmq_stg_conf['vhost'])

    rmq_prod.create_user(username=contract_name,
                         password=rmq_prd_user_password,
                         vhost=rmq_prd_conf['vhost'])

    # Vault
    vlt_conf = app_config['Vault']
    vc = VaultClient(url=vlt_conf['url'],
                     token=vlt_conf['token'])

    vault_path = vlt_conf['secretPath'].format(owner_name=owner,
                                               contract_name=contract_name,
                                               env=app_config['prodEnvName'])
    vault_data = {
        'url': f'amqp://{contract_name}:{rmq_prd_user_password}@{rmq_prd_conf["host"]}/{rmq_prd_conf["vhost"]}'}
    vc.write_secret(path=vault_path, data=vault_data)

    vault_path = vlt_conf['secretPath'].format(owner_name=owner,
                                               contract_name=contract_name,
                                               env=app_config['stgEnvName'])
    vault_data = {
        'url': f'amqp://{contract_name}:{rmq_stg_user_password}@{rmq_stg_conf["host"]}/{rmq_stg_conf["vhost"]}'}
    vc.write_secret(path=vault_path, data=vault_data)

    # GitLab
    k8s_ns_stg_name = app_config['k8sNsTemplate'].format(tenant_name=tenant_std, name=contract_name).replace('.', '-')
    k8s_ns_prod_name = app_config['k8sNsTemplate'].format(tenant_name=tenant_prod, name=contract_name).replace('.', '-')
    gl_conf = app_config['gitlab']
    gl = GitLabWrapper(url=gl_conf['url'],
                       token=gl_conf['token'],
                       prod_ref=gl_conf['prodRef'],
                       stg_ref=gl_conf['stgRef'],
                       argocd_prj_name=gl_conf['argocdPrj'],
                       root_group_name=gl_conf['rootGroup'])

    gl_project = gl.create_contract_repo(name=contract_name,
                                         developers=developers,
                                         stg_env_name=app_config['stgEnvName'],
                                         gitlab_ci_path=gl_conf['gitlabCiPath'],
                                         template_name=gl_conf['templatePrj'],
                                         owner=owner)

    git_repo_url = gl_project.http_url_to_repo
    gl.create_argocd_app(name=contract_name,
                         git_repo_url=git_repo_url,
                         k8s_ns_stg_name=k8s_ns_stg_name,
                         k8s_ns_prod_name=k8s_ns_prod_name,
                         argocd_repo_template=gl_conf['argocdRepoTemplate'],
                         argocd_app_template=gl_conf['argocdAppTemplate'],
                         prod_env_name = app_config['prodEnvName'],
                         stg_env_name = app_config['stgEnvName'])



if __name__ == '__main__':
    app()
