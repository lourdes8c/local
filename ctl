#!/usr/bin/python3
import argparse
import sys
import requests
import json
import shtab
import base64
import time
import re
from uuid import uuid4
from pathlib import Path
from os import path,makedirs
from configparser import ConfigParser
import urllib3
import asyncio
import websockets
from colorama import Fore,Back,Style,init
import logging
import copy

##MAIN CLASS
class Calderactl(object):

        caldera_config_file=""
        caldera_config_dir=""
        manx_command_prompt="$ "
        manx_ability_id ="356d1722-7784-40c4-822b-0cf864b0b36d"
        manx_ability_id_8887="5e8a54ca-2691-4fef-bc48-14de5bcafb24"


        adversary_template={"name":"Nombre del adversary","description":"Descripcion del adversario","atomic_ordering":[{"id":"ability_id1"},{"id":"ability_id2"}],"index":"adversaries","id":"","objective":""}
        ability_template={"index":"abilities",
                                                "id":"",
                                                "name":"<Nombre de la ability>",
                                                "description":"<Descripcion de la ability>",
                                                "tactic":"<Mitre tactic>",
                                                "technique":
                                                        {"attack_id":"<Mitre technique id>",
                                                        "name":"<Mitre nombre de la tecnica>"
                                                        },
                                                        "platforms":
                                                                {"windows":
                                                                        {"psh":
                                                                                {"command":"<comando>",
                                                                                "payloads":["<lista de ficheros>"],
                                                                                "cleanup":"<cleanup command>",
                                                                                "timeout":60
                                                                                }
                                                                        }
                                                                }
                                                }

        operation_template={"index":"operations",
                                                "name":"<nombre de la operacion>",
                                                "group":"<grupo de agentes>",
                                                "adversary_id":"<id del adversario>",
                                                "state":"running",
                                                "planner":"batch",
                                                "autonomous":"1",
                                                "obfuscator":"plain-text",
                                                "auto_close":"1",
                                                "jitter":"4/8",
                                                "source":"basic",
                                                "visibility":"50"}

        ##TIMES FOR EACH OPERATIONS
        operation_name="{}-{}"
        operation_maxWaitTime=180
        operation_maxWaitTime_Purple=10800

        ##SUBCOMMAND ACTIONS DEFINITIONS
        def __init__(self):
                init(autoreset=True)
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                self.parser=self._getParser()
                self.caldera_config_dir=str(Path.home()) + '/.calderactl/'
                self.caldera_config_file='calderactl.conf'
                args = self.parser.parse_args()
                ## SUBCOMMAND AUTH
                if args.subcommands=='auth':
                        if args.auth_subcommands=='view':
                                self._list_configuration()
                        elif  args.auth_subcommands=='init':
                                self._init_configuration()
                        elif args.auth_subcommands== 'add':
                                self._add_configuration()
                        elif args.auth_subcommands == 'switch':
                                self._switch_configuration(args.profile)
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND ABILITIES
                elif args.subcommands=='abilities':
                        if args.abilities_subcommands=='list':
                                self._list_abilities(args.j)
                        elif args.abilities_subcommands=='get':
                                self._get_abilities(args.id,args.j,args.a)
                        elif args.abilities_subcommands=='create':
                                self._create_ability(args.json_file)
                        elif args.abilities_subcommands=='template':
                                self._generate_ability()
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND ADVERSARIES
                elif args.subcommands=='adversaries':
                        if args.adversaries_subcommands=='list':
                                self._list_adversaries(args.j)
                        elif args.adversaries_subcommands=='get':
                                self._list_adversaries_id(args.id,args.j,args.e)
                        elif args.adversaries_subcommands=='create':
                                self._create_adversary(args.json_file)
                        elif args.adversaries_subcommands=='template':
                                self._generate_adversary()
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND AGENTS
                elif args.subcommands=='agents':
                        if args.agents_subcommands=='list':
                                self._list_agents(args.g,args.c)
                        elif args.agents_subcommands=='kill':
                                self._kill_agent(args.paw)
                        elif args.agents_subcommands=='delete':
                                self._delete_agent(args.paw)
                        elif args.agents_subcommands=='clean':
                                self._clean(args.f)
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND SYSTEM
                elif args.subcommands == 'system':
                        if args.system_subcommands=='backup':
                                self._save_state()
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND OPERATIONS
                elif args.subcommands == 'operations':
                        if args.operations_subcommands == 'list':
                                self._list_operations(args.j)
                        elif args.operations_subcommands == 'get':
                                self._get_operation(args.id,args.j,args.e,args.c)
                        elif args.operations_subcommands == 'template':
                                self._generate_operation()
                        elif args.operations_subcommands == 'run':
                                self._run_operation(args.f)
                        elif args.operations_subcommands == 'batch':
                                self._batch_operation(args.file,args.g)
                        elif args.operations_subcommands == 'atomic':
                                self._atomic_operation(args.file,args.g)
                        elif args.operations_subcommands == 'runAll':
                                self._purple_runAll(args.file,args.g,args.p,args.t)
                        elif args.operations_subcommands == 'delete':
                                self._delete_operation(args.id)
                        elif args.operations_subcommands == 'delete_file':
                                self._delete_operation_file(args.file)
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND MANX
                elif args.subcommands == 'manx':
                        if args.manx_subcommands == 'list':
                                self._list_manx_agents()
                        elif args.manx_subcommands == 'interact':
                                self._manx_interact(args.id)
                        elif args.manx_subcommands == 'deploy':
                                self._manx_deploy(args.paw,args.L)
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND LINK
                elif args.subcommands == 'link':
                        if args.link_subcommands == 'get':
                                self._link_get(args.id,args.j)
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND ACCESS
                elif args.subcommands == 'access':
                        if args.access_subcommands=='get':
                                self._access_get(args.paw)
                        elif args.access_subcommands=='run':
                                self._access_run(args.id,args.paw)
                        else:
                                print (self.parser._actions[2].choices[args.subcommands].format_help())
                ##SUBCOMMAND RUN
                elif args.subcommands == 'run':
                        self._command_run(args.paw,args.command)
                ##SUBCOMMAND REPORT
                elif args.subcommands == 'report':
                        self._report(args.id)
                ##NO SUBCOMMAND -> PRINT HELP PANEL
                if not len(sys.argv) > 1:
                        self.parser.print_help()
                        exit(1)

        ##COMMAND ACTIONS DEFINITION
        def _getParser(self):
                main_parser = argparse.ArgumentParser(prog='calderactl',
                                formatter_class= lambda prog: argparse.HelpFormatter(prog,max_help_position=100),
                                description='A Command Line Interface to manage Caldera')
                shtab.add_argument_to(main_parser, ["-completion"])
                subparsers = main_parser.add_subparsers(dest="subcommands")


                ##AUTH
                auth_parser=subparsers.add_parser("auth",help='Commands to manage Caldera connection')
                auth_subparsers=auth_parser.add_subparsers(dest='auth_subcommands')
                auth_subparsers.add_parser('init', help='init authentication')
                auth_subparsers.add_parser('view', help='view  authentication profiles')
                auth_switch = auth_subparsers.add_parser('switch', help='switch  authentication profile')
                auth_switch.add_argument('profile',action='store',help='profile name to switch')
                auth_subparsers.add_parser('add', help='add authentication profile')

                ##ABILITIES
                abilities_parser=subparsers.add_parser("abilities",help='Commands to manage abilities')
                abilities_subparsers=abilities_parser.add_subparsers(dest='abilities_subcommands')
                ab_list = abilities_subparsers.add_parser('list', help='List the avaliable abilities')
                ab_list.add_argument('-j',required=False,action='store_true',help='json output')
                ab_create=abilities_subparsers.add_parser('create', help='Create a new ability (update if exist)')
                ab_create.add_argument('json_file',help='json file with the definition of the ability').complete=shtab.FILE
                ab_get=abilities_subparsers.add_parser('get', help='List a specific ability id')
                ab_get.add_argument('id',action='store',help='id of the ability')
                ab_get.add_argument('-j',required=False,action='store_true',help='json output')
                ab_get.add_argument('-a',required=False,action='store_true',help='returns the adversaries that contains this ability')
                abilities_subparsers.add_parser('template',help='Generate a ability json document template in order to create a new one')


                ##ADVERSARIES
                advesaries_parser = subparsers.add_parser("adversaries",help='Commands to manage adversaries')
                adversaries_subparsers=advesaries_parser.add_subparsers(dest='adversaries_subcommands')
                adv_list = adversaries_subparsers.add_parser('list',help='List the avaliable adversaries')
                adv_list.add_argument('-j',required=False,action='store_true',help='json output')
                adv_create=adversaries_subparsers.add_parser('create', help='Create a new adversary (update if exist)')
                adv_create.add_argument('json_file',help='json file with the definition of the adversary').complete=shtab.FILE
                adv_get=adversaries_subparsers.add_parser('get', help='List a specific adversary id')
                adv_get.add_argument('id',action='store',help='Id of the adversary')
                adv_get.add_argument('-j',required=False,action='store_true',help='json output')
                adv_get.add_argument('-e',required=False,action='store_true',help='detailed ouput')
                adversaries_subparsers.add_parser('template',help='Generate a adversary json document template in order to create a new one')

                ##AGENTS
                agents_parser = subparsers.add_parser("agents",help='Commands to manage agents')
                agents_subparsers=agents_parser.add_subparsers(dest='agents_subcommands')
                agents_list = agents_subparsers.add_parser('list',help='List the avaliable agents')
                agents_list.add_argument('-c',required=False,action='store_true',help='csv output')
                agents_list.add_argument('-g',required=False,action='store',help='filter by group')
                agent_kill = agents_subparsers.add_parser('kill',help='kill an agent')
                agent_kill.add_argument('paw',action='store',help='Paw of the agent to kill')
                agent_delete = agents_subparsers.add_parser('delete',help='delete agent')
                agent_delete.add_argument('paw',action='store',help='Paw of the agent to delete')
                agents_clean = agents_subparsers.add_parser('clean',help='clean the agents that are marked as untrusted but are currently running')
                agents_clean.add_argument('-f',required=False,action='store_true',help='clean withouth confirmation')

                ##SYSTEM
                system_parser = subparsers.add_parser("system",help='Commands to managed the system')
                system_subparsers = system_parser.add_subparsers(dest='system_subcommands')
                system_subparsers.add_parser('backup',help='create a backup of the Caldera memory based database')

                ##OPERATIONS
                operations_parser = subparsers.add_parser("operations",help='Commands to managed the operations')
                operations_subparsers = operations_parser.add_subparsers(dest='operations_subcommands')
                oper_list = operations_subparsers.add_parser('list',help='list the operations')
                oper_list.add_argument('-j',required=False ,action='store_true',help='json output')
                oper_get = operations_subparsers.add_parser('get',help='list a specific operations id')
                oper_get.add_argument('id',action='store',help='id of the operation')
                oper_get.add_argument('-j',required=False ,action='store_true',help='json output')
                oper_get.add_argument('-e',required=False ,action='store_true',help='extended output')
                oper_get.add_argument('-c',required=False ,action='store_true',help='csv output')
                oper_run=operations_subparsers.add_parser('run', help='Run a new operation')
                oper_run_grp = oper_run.add_mutually_exclusive_group()
                oper_run_grp.required=True
                (oper_run_grp.add_argument('-f',default=".",action='store',help='Json file with the definition of the operation')).complete=shtab.FILE
                oper_run_grp.add_argument('-a',action='store',help='Name of the adversary to execute.')
                operations_subparsers.add_parser('template',help='Generate a operation json document template in order to create a new one')
                oper_batch= operations_subparsers.add_parser('batch',help='run a batch of operations one by one')
                oper_batch.add_argument('file',help='text file with the name of the adversaries you wanto to execute').complete=shtab.FILE
                oper_batch.add_argument('-g',required=True,action='store',help='group of the operation')
                oper_atomic= operations_subparsers.add_parser('atomic',help='run atomic operation one by one')
                oper_atomic.add_argument('file',help='text file with the name of the adversaries you wanto to execute').complete=shtab.FILE
                oper_atomic.add_argument('-g',required=True,action='store',help='group of the operation')
                oper_purple_run_all= operations_subparsers.add_parser('runAll',help='run a batch of operation for all Purple Adversaries')
                oper_purple_run_all.add_argument('-p',required=True, action='store', help='planner to execute all adversaries')
                oper_purple_run_all.add_argument('file',help='text file with the name of the adversaries you wanto to execute').complete=shtab.FILE
                oper_purple_run_all.add_argument('-g',required=True,action='store',help='group of the operation')
                oper_purple_run_all.add_argument('-t',required=False,action='store',help='Max time to wait for end the operation in SECONDS, by default 3 hours')
                oper_delete= operations_subparsers.add_parser('delete',help='delete operation')
                oper_delete.add_argument('id',help='operation id to delete')
                oper_delete_file= operations_subparsers.add_parser('delete_file',help='delete operations')
                oper_delete_file.add_argument('file',help='text file with operations id to delete')

                ##MANX
                manx_parser = subparsers.add_parser("manx",help='Commands to managed the MANX plugin')
                manx_subparsers = manx_parser.add_subparsers(dest='manx_subcommands')
                manx_subparsers.add_parser('list',help='list the Manx agents')
                manx_deploy = manx_subparsers.add_parser('deploy',help='deploy a Manx agent and coomunicate via with it with interact option')
                manx_deploy.add_argument('paw',action='store',help='paw of the agent')
                manx_deploy.add_argument('-L',required=False,action='store_true',help='deploy a Manx agent with Listener (PRE machine 8887)')
                manx_interact = manx_subparsers.add_parser('interact',help='interact with a Manx agent')
                manx_interact.add_argument('id',action='store',help='id of the manx agent')

                ##LINKS
                link_parser = subparsers.add_parser("link",help='Commands to managed the links')
                link_subparsers = link_parser.add_subparsers(dest='link_subcommands')
                link_get = link_subparsers.add_parser('get',help='get a specific link id')
                link_get.add_argument('id',action='store',help='id of the link')
                link_get.add_argument('-j',action='store_true',help='json format')

                ##ACCESS
                access_parser = subparsers.add_parser("access",help='Commands to managed Access Module')
                access_subparser = access_parser.add_subparsers(dest='access_subcommands')
                access_get = access_subparser.add_parser('get',help='get de abilities status of a specific agent')
                access_get.add_argument('paw',action='store',help='paw of the agent')
                access_run = access_subparser.add_parser('run',help='run a specific ability on an agent')
                access_run.add_argument('id',action='store', help='id of the ability to run')
                access_run.add_argument('paw',action='store',help='paw of the agent')

                ##RUN
                run_parser = subparsers.add_parser("run",help='Launch commands against agents')
                run_parser.add_argument('paw',action='store',help='paw of the agent')
                run_parser.add_argument('command',action='store',help='command to launch')

                ##REPORT
                report_parser = subparsers.add_parser("report",help='Report abilities')
                report_subparsers=report_parser.add_subparsers(dest='adversaries_subcommands')
                adv_get=report_subparsers.add_parser('get', help='get a report for a specific adversary id')
                adv_get.add_argument('id',action='store',help='adversary id to search')

                return main_parser

        ##########################
        ## FUNCTION DEFINITIONS ##
        ##########################

        def _link_get(self,id,jsonFormat=False):
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                data_result={"index":"result","link_id":int(id)}
                r_result = requests.post(url + '/api/v2',headers=headers,json=data_result,verify=False)

                link = r_result.json()

                if link:
                        if jsonFormat:
                                print (link)
                        else:
                                print('')
                                print('{:6}\t{:36}\t{:40}\t{:15}\t{:6}\t{:25}\t{:19}\t{:2}'.format('id','ability_id','ability name','tech id','paw','hostname','finish','status'))
                                link_id=id
                                ab_id=link['link']['ability']['ability_id']
                                ab_name=link['link']['ability']['name']
                                tech_id=link['link']['ability']['technique_id']
                                paw=link['link']['paw']
                                host=link['link']['host']
                                finish=link['link']['finish']
                                if link['link']['status']==0:
                                        status='OK'
                                else:
                                        status='KO'
                                print('{:6}\t{:36}\t{:40}\t{:15}\t{:6}\t{:25}\t{:19}\t{:2}'.format(link_id,ab_id,ab_name,tech_id,paw,host,finish,status))
                                print('')
                                print ('\tExecutors: {}'.format(link['link']['ability']['executors']))
                                print('\tCommand: {}'.format(base64.b64decode(link['link']['command']).decode('utf-8')))
                                print('\tOutput:')
                                if link['output']:
                                        output=base64.b64decode(link['output']).splitlines()

                                        for line in output:
                                                print('\t{}'.format(line.decode('utf-8',errors='ignore')))

                                else:
                                        print('\t{}'.format('No output returned'))
                                print('')

        def _manx_deploy(self,paw,listenerFlag):
                if listenerFlag:
                        self._access_run(self.manx_ability_id_8887,paw)
                else:
                        self._access_run(self.manx_ability_id,paw)


        async def _run(self,id, command):
                url,_=self._getConnection()
                ip=url.split("//")[1]
                uri = "ws://" + ip + ":8000/manx/" + str(id)
                async with websockets.connect(uri) as websocket:

                        await websocket.send(command)

                        response = json.loads(await websocket.recv())
                        print(response['response'].replace("\r\n","\n"))
                        self.manx_command_prompt=response['pwd'] + "$ "

        def _manx_interact(self, id):
                while True:
                        command = input(self.manx_command_prompt)
                        if "exit" in command:
                                break
                        loop = asyncio.get_event_loop()
                        loop.run_until_complete(self._run(id,command))

        def _list_manx_agents(self):
                url,key=self._getConnection()
                r_manx = requests.post(url + '/plugin/manx/sessions',verify=False)
                manx_agents=r_manx.json()

                fields={'id':'{:10}','host':'{:25}','group':'{:5}','pid':'{:8}','location':'{:15}','username':'{:25}','paw':'{:5}','platform':'{:8}','contact':'{:7}','executors':'{:10}','privilege':'{:10}','trusted':'{:5}','last_seen':'{:20}'}

                data={"index":"agents"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)

                print('\t'.join(fields[field].format(field) for field in fields.keys()))
                for agent in r.json():
                        for m_agent in manx_agents:
                                if agent['paw']==m_agent['info']:
                                        agent['id'] = m_agent['id']
                                        print ('\t'.join(fields[field].format(str(agent[field])) for field in fields.keys()))

        def _list_operations(self,jsonFormat=False):
                fields = {'id': '{:6}', 'name': '{:55}', 'host_group': '{:10}', 'state': '{:10}', 'start': '{:30}'}
                url,key=self._getConnection()
                data={"index":"operations"}
                headers = {'KEY': key, 'content-type': 'application/json; charset=utf-8'}
                r = requests.post(url + '/api/v2/operations', headers=headers, json=data, verify=False)
                if jsonFormat:
                    print(r.text)
                else:
                    print('\t'.join(fields[field].format(field) for field in fields.keys()))
                   
                    for operation in r.json():
                          if not isinstance(operation, dict):
                            print(f"ERROR: 'operation' is not a dictionary: {operation}")
                            continue

                          if 'id' not in operation.keys() or 'name' not in operation.keys():
                            print(f"ERROR: 'id' or 'name' not present in operation {operation}")
                            continue

                          str_buf=[]
                          for field in fields.keys():
                                if field != 'host_group':
                                    if isinstance(operation, dict) and field in operation and isinstance(operation[field], str):
                                       str_buf.append(fields[field].format(operation[field]))
                                    elif field in operation and operation[field] is not None:
                                        str_buf.append(fields[field].format(str(operation[field])))
                                       
                                    else:
                                       print(f"ERROR: Field '{field}' not present in operation {operation}")
                                       str_buf.append(fields[field].format(''))
                                                
                                else:
                                   if 'host_group' in operation.keys():
                                       if len(operation['host_group']) != 0 and 'group' in operation['host_group'][0]:
                                           str_buf.append(fields[field].format(str(operation['host_group'][0]['group'])))
                                       else:
                                           print(f"ERROR: Field 'group' not present in operation's host_group {operation}")
                                           str_buf.append(fields[field].format(''))
                                   else:
                                       print(f"ERROR: Field 'host_group' not present in operation {operation}")
                                       str_buf.append(fields[field].format(''))
                          print('\t'.join(str_buf))
                          str_buf.clear()
                    

        def _get_operation(self,id,jsonFormat=False,extended=False,csvFormat=False):
                fields={'id':'{:6}','name':'{:55}','host_group':'{:10}','state':'{:10}','start':'{:30}'}
                url,key=self._getConnection()
                data={"index":"operations","id":int(id)}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)

                if jsonFormat:
                        print (r.text)
                else:
                        operation=r.json()[0]
                        adv_id = operation['adversary']['adversary_id']
                        adv_name = operation['adversary']['name']
                        chains = operation['chain']
                        str_buf=[]
                        if not csvFormat:
                                print('\t'.join(fields[field].format(field) for field in fields.keys()))
                        for field in fields.keys():
                                if field != 'host_group':
                                        str_buf.append(fields[field].format(str(operation[field])))
                                else:
                                        str_buf.append(fields[field].format( str(operation[field][0]['group']) if len(operation[field])!=0 else ""))
                        if not csvFormat:
                                print('\t'.join(str_buf))
                                print('|_ {:30}\t{:30}'.format(adv_id,adv_name))
                                print('\t|   {:6}\t{:36}\t{:40}\t{:15}\t{:6}\t{:25}\t{:19}\t{:2}'.format('id','ability_id','ability name','tech id','paw','hostname','finish','status'))
                        for chain in chains:
                                chain_id =chain['id']
                                ab_id=chain['ability']['ability_id']
                                if chain['cleanup'] == 1:
                                        ab_name=chain['ability']['name'] + "(Cleanup)"
                                else:
                                        ab_name=chain['ability']['name']
                                tech_id=chain['ability']['technique_id']
                                paw=chain['paw']
                                host=chain['host']
                                finish=chain['finish']
                                color=""
                                if chain['status']==0:
                                        status=Fore.GREEN + 'success'
                                elif chain['status']==-2:
                                        status="discarted"
                                elif chain['status']==1:
                                        status=Fore.RED + 'failure'
                                elif chain['status']==124:
                                        status=Fore.BLUE +'timeout'
                                elif chain['status']==-3 and chain['collect'] == None:
                                        status=Fore.YELLOW + 'Collecting'
                                elif chain['status']==-3 and chain['collect'] != None:
                                        status=Fore.LIGHTGREEN_EX + 'Running'
                                elif chain['status']==-4:
                                        status='untrusted'
                                elif chain['status']==-5:
                                        status='visibility'
                                else:
                                        status='queued'
                                if not csvFormat:
                                        print('\t|__ {:6}\t{:36}\t{:40}\t{:15}\t{:6}\t{:25}\t{:19}\t{:10}'.format(chain_id,ab_id,ab_name,tech_id,paw,host,finish,status))
                                else:
                                        if chain['cleanup'] == 1:  #En el informe no mostramos los cleanups
                                                pass
                                        else:
                                                operation_part=';'.join([str(operation['id']),operation['name'],str(operation['host_group'][0]['group']),operation['state'],operation['start']])
                                                adversary_part=';'.join([adv_id,adv_name])
                                                chain_part=';'.join([str(chain_id),str(ab_id),ab_name,tech_id,paw,host,finish,status])
                                                print (';'.join([operation_part,adversary_part,chain_part]))

                                if extended:
                                        data_result={"index":"result","link_id":chain['id']}
                                        r_result = requests.post(url + '/api/v2',headers=headers,json=data_result,verify=False)
                                        print('\t|\t')
                                        print('\t|\tCommand: {}'.format(base64.b64decode(chain['command']).decode('utf-8')))
                                        print('\t|\tOutput:')
                                        if 'output' in r_result.json():
                                                output=base64.b64decode(r_result.json()['output']).splitlines()

                                                for line in output:
                                                        print('\t|\t{}'.format(line.decode('utf-8',errors='ignore')))

                                        else:
                                                print('\t|\t{}'.format('No output returned'))
                                        print('\t|\t')
                        if len(chains) == 0:
                            operation_part=';'.join([str(operation['id']),operation['name'],str(operation['host_group'][0]['group']),    operation['state'],operation['start']])
                            adversary_part=';'.join([adv_id,adv_name])
                            chain_part=""
                            print (';'.join([operation_part,adversary_part,chain_part]))

        def _generate_operation(self):
                print(json.dumps(self.operation_template))

        def _status_operation(self,id):
                url,key=self._getConnection()
                data={"index":"operations","id":int(id)}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)
                #print (r.json()[0]['state'])

                return (r.json()[0]['state'])

        def _delete_agent(self,pawlist):
                for paw in pawlist.split(','):
                        data={"index":"agents"}
                        data['paw']=paw

                        url,key=self._getConnection()
                        headers={'KEY':key,'content-typer':'application/json; charset=utf8'}

                        r = requests.delete(url + '/api/v2',headers=headers,json=data,verify=False)
                        print (r.text)


        def _kill_agent(self,paw):
                data={"index":"agents","watchdog":1,"sleep_min":3,"sleep_max":3}
                data['paw']=paw
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}

                r = requests.put(url + '/api/v2',headers=headers,json=data,verify=False)
                print (r.text)

        def _clean(self,no_confirm=False):
                deletelist=[]
                url,key=self._getConnection()
                data={"index":"agents"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)
                agents=r.json()
                for agent in agents:
                        if agent['trusted'] == False:
                                if self._is_running_agent(agent['host'],r.json()):
                                        deletelist.append(agent['paw'])
                                else:
                                        olders=self._get_olders(agents,agent)
                                        for older in olders:
                                                if older not in deletelist:
                                                        deletelist.append(older)
                if len(deletelist) > 0:
                        if no_confirm:
                                self._delete_agent(','.join(deletelist))
                        else:
                                print('The following agents will be deleted: {}'.format(','.join(deletelist)))
                                delete=input('Y/N?')
                                if delete=='Y':
                                        self._delete_agent(','.join(deletelist))

        def _get_olders(self,agents,agent_s):
                deletelist=[]
                for agent in agents:
                        if agent['host'] == agent_s['host'] and agent['paw'] != agent_s['paw']:
                                if agent['last_seen'] < agent_s['last_seen']:
                                                deletelist.append(agent['paw'])
                return deletelist


        def _is_running_agent(self,host,agents):
                for agent in agents:
                        if agent['host']==host and agent['trusted']==True:
                                return True

                return False

        def _buildOperation(self,adversaries,adv_filter,group,planner = None):

                operation=None
                adv_filter="^{}$".format(adv_filter)

                for adversary  in adversaries:
                        match=re.match(adv_filter,adversary['name'])
                        if match:
                                operation=copy.deepcopy(self.operation_template)
                                logging.info("Adversary found {}".format(adversary['name']))
                                operation_name=self.operation_name.format(group,adversary['name'].split(" ")[0])
                                operation["name"] = operation_name
                                operation["group"] = group
                                operation["adversary_id"] = adversary['adversary_id']
                                operation["source"] = "SGT"
                                if planner is not None:
                                        operation["planner"] = planner

                return operation

        def _batch_operation(self,file,group):

                untrusted=False

                logFormatter = logging.Formatter("%(asctime)s %(levelname)s - %(message)s",'%d-%m-%Y %H:%M:%S')
                logger = logging.getLogger()
                logger.setLevel(logging.INFO)

                fileHandler = logging.FileHandler("{0}/{1}.log".format(".", "calderactl_batch"))
                fileHandler.setFormatter(logFormatter)
                logger.addHandler(fileHandler)

                consoleHandler = logging.StreamHandler()
                consoleHandler.setFormatter(logFormatter)
                logger.addHandler(consoleHandler)



                #check agents
                logger.info(f"Checking agents for group {group}")


                fields={'host':'{:25}','group':'{:5}','username':'{:25}','paw':'{:5}','platform':'{:8}','contact':'{:7}','executors':'{:10}','privilege':'{:10}','trusted':'{:5}','last_seen':'{:20}'}
                url,key=self._getConnection()
                data={"index":"agents"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2/agents',headers=headers,json=data,verify=False)

                for agent in r.json():
                        if agent['group'] == group:
                                if agent['trusted']==True:
                                        agent['trusted']=Fore.GREEN + Style.BRIGHT  + 'True' + Style.RESET_ALL
                                        #agent['host']=Fore.GREEN + Style.BRIGHT + agent['host']
                                else:
                                        agent['trusted']=Back.RED + Fore.WHITE + Style.BRIGHT + 'False' + Style.RESET_ALL
                                        untrusted=True
                                logger.info ('\t'.join(fields[field].format(str(agent[field])) for field in fields.keys()))


                if untrusted:
                        logger.warning("Untrusted agents found for this group!")
                        logger.warning("")
                        input_value = input("Do you want to really continue? (Y/N) ")
                        if input_value != "Y":
                                logger.info("Aborting execution...")
                                return


                f_operOK = open ("./operations_OK","w")
                f_operKO = open ("./operations_KO","w")
                url,key=self._getConnection()

                data={"index":"adversaries"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                logger.info("Loading all caldera adversaries...")
                r_adv = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)
                logger.info("Loaded {} caldera adversaries".format(len(r_adv.json())))
                for ttp in open(file,"r").readlines():
                        ttp=ttp.strip("\n")

                        operation = self._buildOperation(r_adv.json(),ttp,group)
                        if operation == None:
                                logger.error("{} not found!".format(ttp))
                        else:
                                operation_name=operation['name']
                                logger.info("Launching operation {} ...".format(operation['name']))

                                r_oper = requests.put(url + '/api/v2',headers=headers,json=operation,verify=False)
                                operId=r_oper.json()[0]['id']
                                wait_time=0
                                while True:
                                        oper_status=self._status_operation(operId)
                                        if ( oper_status == "running"):
                                                logger.info ("Waiting for {}({}) to be completed...".format(operation_name,operId))
                                                if (wait_time > self.operation_maxWaitTime):
                                                        logger.error("Max waiting time exceeded!")
                                                        f_operKO.write(f"{ttp}\n")
                                                        break
                                                wait_time+=10
                                                time.sleep(10)
                                        elif (oper_status == "finished"):
                                                logger.info ("{} ({}) finished!".format(operation_name,operId))
                                                f_operOK.write(f"{ttp}\n")
                                                break
                                        else:
                                                logger.warning ("operation {} ({}) finished with this status! {}".format(operation_name,operId,oper_status))
                f_operOK.close()
                f_operKO.close()

        def _atomic_operation(self,file,group):

                untrusted=False

                logFormatter = logging.Formatter("%(asctime)s %(levelname)s - %(message)s",'%d-%m-%Y %H:%M:%S')
                logger = logging.getLogger()
                logger.setLevel(logging.INFO)

                fileHandler = logging.FileHandler("{0}/{1}.log".format(".", "calderactl_atomic"))
                fileHandler.setFormatter(logFormatter)
                logger.addHandler(fileHandler)

                consoleHandler = logging.StreamHandler()
                consoleHandler.setFormatter(logFormatter)
                logger.addHandler(consoleHandler)



                #check agents
                logger.info(f"Checking agents for group {group}")


                fields={'host':'{:25}','group':'{:5}','username':'{:25}','paw':'{:5}','platform':'{:8}','contact':'{:7}','executors':'{:10}','privilege':'{:10}','trusted':'{:5}','last_seen':'{:20}'}
                url,key=self._getConnection()
                data={"index":"agents"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2/agents',headers=headers,json=data,verify=False)

                for agent in r.json():
                        if agent['group'] == group:
                                if agent['trusted']==True:
                                        agent['trusted']=Fore.GREEN + Style.BRIGHT  + 'True' + Style.RESET_ALL
                                        #agent['host']=Fore.GREEN + Style.BRIGHT + agent['host']
                                else:
                                        agent['trusted']=Back.RED + Fore.WHITE + Style.BRIGHT + 'False' + Style.RESET_ALL
                                        untrusted=True
                                logger.info ('\t'.join(fields[field].format(str(agent[field])) for field in fields.keys()))


                if untrusted:
                        logger.warning("Untrusted agents found for this group!")
                        logger.warning("")
                        input_value = input("Do you want to really continue? (Y/N) ")
                        if input_value != "Y":
                                logger.info("Aborting execution...")
                                return


                f_operOK = open ("./operations_OK","w")
                f_operKO = open ("./operations_KO","w")
                url,key=self._getConnection()

                data={"index":"adversaries"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                logger.info("Loading all caldera adversaries...")
                r_adv = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)
                logger.info("Loaded {} caldera adversaries".format(len(r_adv.json())))
                for ttp in open(file,"r").readlines():
                        ttp=ttp.strip("\n")

                        operation = self._buildOperation(r_adv.json(),ttp,group,"atomic")
                        if operation == None:
                                logger.error("{} not found!".format(ttp))
                        else:
                                operation_name=operation['name']
                                logger.info("Launching operation {} ...".format(operation['name']))

                                r_oper = requests.put(url + '/api/v2',headers=headers,json=operation,verify=False)
                                operId=r_oper.json()[0]['id']
                                wait_time=0
                                while True:
                                        oper_status=self._status_operation(operId)
                                        if ( oper_status == "running"):
                                                logger.info ("Waiting for {}({}) to be completed...".format(operation_name,operId))
                                                if (wait_time > self.operation_maxWaitTime):
                                                        logger.error("Max waiting time exceeded!")
                                                        f_operKO.write(f"{ttp}\n")
                                                        break
                                                wait_time+=10
                                                time.sleep(10)
                                        elif (oper_status == "finished"):
                                                logger.info ("{} ({}) finished!".format(operation_name,operId))
                                                f_operOK.write(f"{ttp}\n")
                                                break
                                        else:
                                                logger.warning ("operation {} ({}) finished with this status! {}".format(operation_name,operId,oper_status))
                f_operOK.close()
                f_operKO.close()

        def _purple_runAll(self, file, group, planner, maxTime):

                if maxTime is not None:
                        self.operation_maxWaitTime_Purple = maxTime

                print(self.operation_maxWaitTime_Purple)
                return

                logging.basicConfig(format='%(asctime)s %(levelname)s - %(message)s', datefmt='%d-%m-%Y %H:%M:%S',level=logging.INFO)

                url,key=self._getConnection()

                data={"index":"adversaries"}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                logging.info("Loading all caldera adversaries...")
                r_adv = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)
                logging.info("Loaded {} caldera adversaries".format(len(r_adv.json())))
                for ttp in open(file,"r").readlines():
                        ttp=ttp.strip("\n")

                        operation = self._buildOperation(r_adv.json(),ttp,group, planner)
                        print(operation)
                        if operation == None:
                                logging.error("{} not found!".format(ttp))
                        else:
                                operation_name=operation['name']
                                logging.info("Launching operation {} ...".format(operation['name']))

                                r_oper = requests.put(url + '/api/v2',headers=headers,json=operation,verify=False)
                                operId=r_oper.json()[0]['id']
                                wait_time=0
                                while True:
                                        oper_status=self._status_operation(operId)
                                        if ( oper_status == "running"):
                                                logging.info ("Waiting for {}({}) to be completed...".format(operation_name,operId))
                                                if wait_time > self.operation_maxWaitTime_Purple:
                                                        logging.error("Max waiting time exceeded!")
                                                        break
                                                wait_time+=10
                                                time.sleep(10)
                                        elif (oper_status == "finished"):
                                                logging.info ("{} ({}) finished!".format(operation_name,operId))
                                                break
                                        else:
                                                logging.warning ("operation {} ({}) finished with this status! {}".format(operation_name,operId,oper_status))
                f_operOK.close()
                f_operKO.close()


        def _delete_operation(self,id):
            url,key=self._getConnection()
            data={"index":"operations","id":int(id)}
            headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
            r = requests.delete(url + '/api/v2',headers=headers,json=data,verify=False)
            print(r.content.decode('utf-8'))

        def _delete_operation_file(self,file):
                url,key=self._getConnection()
                with open(file) as f:
                        for line in f:
                                print("Deleting operation:", line)
                                data={"index":"operations","id":int(line)}
                                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                                r = requests.delete(url + '/api/v2',headers=headers,json=data,verify=False)
                                print(r.content.decode('utf-8'))

        def _run_operation(self,file):
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}

                with open(file) as f:
                        data=json.load(f)
                        r = requests.put(url + '/api/v2',headers=headers,json=data,verify=False)

                        print (r.json()[0]['id'])

#Los principales cambios son la adición de la comprobación isinstance(agent, dict) antes de acceder a los campos del agente y la eliminación de las asignaciones agent['trusted']
        def _list_agents(self, group=None, csv_format=False):
                fields = {'host': '{:25}', 'group': '{:5}', 'username': '{:25}', 'paw': '{:5}', 'platform': '{:8}', 'contact': '{:7}', 'executors': '{:10}', 'privilege': '{:10}', 'trusted': '{:5}', 'last_seen': '{:20}'}
                url, key = self._getConnection()
                data = {"index": "agents"}
                headers = {'KEY': key, 'accept': 'application/json'}
                r = requests.post(url + '/api/v2/agents', headers=headers, verify=False)
                if csv_format:
                        csv_fields = ["paw", "group", "architecture", "platform", "server", "username", "location", "pid", "ppid", "trusted", "last_seen", "sleep_min", "sleep_max", "executors", "privilege", "display_name", "exe_name", "host", "watchdog", "contact"]
                        for agent in r.json():
                            if isinstance(agent, dict):
                                                           
                                if group is None:
                                        agent['executors'] = '|'.join(agent['executors'])
                                        agent['trusted'] = agent.get('trusted', False)
                                        print(';'.join(str(agent[field]) for field in csv_fields))
                                else:
                                        if agent['group'] == group:
                                                agent['executors'] = '|'.join(agent['executors'])
                                                agent['trusted'] = agent.get('trusted', False)
                                                print(';'.join(str(agent[field]) for field in csv_fields))
                else:

                         print(Fore.WHITE + Style.BRIGHT + '\t'.join(fields[field].format(field) for field in fields.keys()))
                         for agent in r.json():
                             if isinstance(agent, dict):
                                if group is None:
                                        agent['trusted'] = agent.get('trusted', False)
                                        if agent['trusted']:
                                            agent['trusted'] = Fore.GREEN + Style.BRIGHT + 'True' + Style.RESET_ALL
                                                #agent['host']=Fore.GREEN + Style.BRIGHT + agent['host']
                                        else:
                                            agent['trusted'] = Back.RED + Fore.WHITE + Style.BRIGHT + 'False' + Style.RESET_ALL
                                        print('\t'.join(fields[field].format(str(agent.get(field, ""))) for field in fields.keys()))
                                else:
                                        if agent['group'] == group:
                                            agent['trusted'] = agent.get('trusted', False)
                                            if agent['trusted']:
                                                agent['trusted'] = Fore.GREEN + Style.BRIGHT + 'True' + Style.RESET_ALL
                                                        #agent['host']=Fore.GREEN + Style.BRIGHT + agent['host']
                                            else:
                                                agent['trusted'] = Back.RED + Fore.WHITE + Style.BRIGHT + 'False' + Style.RESET_ALLL
                                            print('\t'.join(fields[field].format(str(agent.get(field, ""))) for field in fields.keys()))

        def _get_adversaries(self):
                #data={"index":"adversaries"}
                url,key=self._getConnection()
                headers={'KEY':key,'accept':'application/json'}
                r = requests.get(url + '/api/v2/adversaries',headers=headers,verify=False)

                return r.json()

        def _get_abilities(self,id,jsonFormat=False,a=False):
                printed_header=False
                fields={'ability_id':'{:35}','name':'{:35}','tactic':'{:20}','technique_id':'{:10}','technique_name':'{:20}'}
                fields_body=["name","platform","command","payloads","cleanup","timeout"] #delete "test"

                if a:
                        for adv in self._get_adversaries():
                                for atomic in adv['atomic_ordering']:
                                        if atomic['ability_id'] == id:
                                                self._list_adversaries_id(adv['adversary_id'])

                else:
                        url,key=self._getConnection()
                        data={"index":"abilities","ability_id":id}
                        headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                        r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)

                        if jsonFormat:
                                print (r.text)
                        else:
                                print('\t'.join(fields[field].format(field) for field in fields.keys()))
                                for ability in r.json():
                                        if not printed_header:
                                                print ('\t'.join(fields[field].format(str(ability[field])) for field in fields.keys()))
                                                printed_header=True
                                                print ('\t|')
                                        for field in fields_body:
                                            for filed in ability['executors']:
                                                if field=="command":
                                                        #filed["command"]=base64.b64decode(filed['command']).decode('utf-8')
                                                        print ("\t|_ {}: {}".format("Command",str(filed[field])))
                                                elif field=="cleanup":
                                                        #print ("\t|_ {}: {}".format("Cleanup",";".join(base64.b64decode(cleanup).decode('utf-8') for cleanup in ability['cleanup'])))
                                                        print ("\t|_ {}: {}".format("Cleanup",str(filed[field])))
                                                elif field=="platform":
                                                        print ("\t|_ {}: {}".format("Platform",str(filed[field])))
                                                elif field=="payloads":
                                                        print ("\t|_ {}: {}".format("Payloads",str(filed[field])))
                                                elif field=="name":
                                                        print ("\t|_ {}: {}".format("Executors",str(filed[field])))
                                                elif field=="timeout":
                                                        print ("\t|_ {}: {}".format("Timeout",str(filed[field])))
                                                else:
                                                        print ("\t|_ {}: {}".format(field,str(ability[field])))
                                        print ("")

        ##ERROR_TO_SOLVE
        # Se ha modificado el campo executor -> executors | mejor opción es quitar el campo 'executors':'{:5}' y 'platform':'{:8}'
        # Se ha modificado el field para acceder a la variable "ability". Sin embargo, esto no es correcto, ya que "field" es solo una cadena que contiene el nombre de un campo, no el valor de un campo.
        def _list_abilities(self, jsonFormat=False):
                fields = {'ability_id': '{:35}', 'name': '{:35}', 'tactic': '{:20}', 'technique_id': '{:10}', 'technique_name': '{:20}'}
                field_child = ['name', 'platform']
                url, key = self._getConnection()

                data = {'index': 'abilities'}
                headers = {'KEY': key, 'content-type': 'application/json; charset=utf8'}
                r = requests.get(url + '/api/v2/abilities', headers=headers, verify=False)
                rest = r.json()
                print(rest)
                if jsonFormat:
                        print(r.text)
                else:
                        #Crea las cabeceras de la tabla.
                        print('\t'.join(fields[field].format(field) for field in fields.keys()))
                        for ability in r.json():
                                name = ability.get('name')
                                platform = ability.get('platform')

                                print('\t'.join(fields[field].format(str(ability.get(field))) for field in fields.keys()))
                                print(name)
                                print(platform)
                        #Ordena el contenido de fields en las cabeceras
                        #for ability in r.json():
                         #   for child in field_child:
                          #      for filed in ability['executors']:
                           #         for field in fields.keys():
                                        #print ('\t'.join(fields[field].format(str(ability[field]))))
                                        #if field=="executors":
                                        #    print ('\t'.join(fields['executors'].format(str(filed['name']))))
                                        #elif field=="platform":
                                        #    print ('\t'.join(fields['platform'].format(str(filed['platform']))))
                                        #else:
                                        #    print ('\t'.join(fields[field].format(str(ability[field]))))
                                    #print (platform['platform'])

        def _create_ability(self,file):
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}

                with open(file) as f:
                        data=json.load(f)
                        r = requests.put(url + '/api/rest',headers=headers,json=data,verify=False)

                        print (r.text)

        def _generate_ability(self):
                ability_id=str(uuid4())
                self.ability_template['id']=ability_id
                print (json.dumps(self.ability_template))

        def _list_adversaries_id(self,id,jsonFormat=False,extended=False):
                fields={'adversary_id':'{:35}','name':'{:15}','description':'{:40}'}
                atomic_fields={'ability_id':'{:40}','name':'{:40}','technique_id':'{:10}','executors':'{:5}','platform':'{:8}','technique_name':'{:20}'}
                data={"index":"adversaries","adversary_id":id}
                url,key=self._getConnection()

                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)

                if jsonFormat:
                        print(r.text)
                else:
                        print('\t'.join(fields[field].format(field) for field in fields.keys()))
                        for ability in r.json():
                                print ('\t'.join(ability[field] for field in fields))
                                for atomic in ability['atomic_ordering']:
                                        print("|__ %s" %('\t'.join(atomic_fields[field].format(str(atomic[field]).replace("\n","")) for field in atomic_fields.keys())))
                                        if extended:
                                                fields_body=["platform","executors","payloads","test","cleanup","timeout"]
                                                for field in fields_body:
                                                        if field=="test":
                                                                atomic["test"]=base64.b64decode(atomic['test']).decode('utf-8')
                                                                print ("\t|_ {}: {}".format("Command",str(atomic[field])))
                                                        elif field=="cleanup":
                                                                print ("\t|_ {}: {}".format("Cleanup",";".join(base64.b64decode(cleanup).decode('utf-8') for cleanup in atomic['cleanup'])))
                                                        else:
                                                                print ("\t|_ {}: {}".format(field,str(atomic[field])))
                                                print("")


        def _list_adversaries(self,jsonFormat=False):
                fields={'adversary_id':'{:35}','name':'{:25}','description':'{:40}'}
                #data={"index":"adversaries"}
                url,key=self._getConnection()
                headers={'KEY':key,'accept':'application/json'}
                r = requests.get(url + '/api/v2/adversaries',headers=headers,verify=False)    
                if jsonFormat:
                        print (r.text)
                else:
                        print('\t'.join(fields[field].format(field) for field in fields.keys()))
                        for adversary in r.json():
                                print ('\t'.join(fields[field].format(str(adversary[field]).replace("\n","")) for field in fields.keys()))


        def _generate_adversary(self):
                adversary_id=str(uuid4())
                self.adversary_template['id']=adversary_id
                print (json.dumps(self.adversary_template))

        def _create_adversary(self,file):
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}

                with open(file) as f:
                        data=json.load(f)
                        r = requests.put(url + '/api/v2',headers=headers,json=data,verify=False)
                        print (r.text)

        ##AUTH VIEW [ACTIONS]
        def _list_configuration(self):
                if path.exists(self.caldera_config_dir + self.caldera_config_file):
                        parser = ConfigParser()
                        parser.read(self.caldera_config_dir + self.caldera_config_file)
                        ##Debe de Existir en .calderactl directory the file calderactl.conf with [PROFILE] -> profilelist and selectedprofile
                        if parser.has_section('PROFILES'):
                                for profile in parser.get('PROFILES', 'profilelist').split(','):
                                        if parser['PROFILES']['selectedprofile']==profile:
                                                print ('**[{}]'.format(profile))
                                        else:
                                                print ('[{}]'.format(profile))
                                        if parser.has_option(profile,'url'):
                                                print (parser.get(profile,'url'))
                                                if parser.has_option(profile,'key'):
                                                        print (parser.get(profile, 'key'))
                                        else:
                                                print ('ERROR: url option not in file %s ' %(self.caldera_config_file))
                        else:
                                print ('ERROR: PROFILES section not found in file %s ' %(self.caldera_config_file))
                else:
                        print ('ERROR: no config file found! execute calderactl auth -I,--init to setup the connection ')

        #Permite añadir un nuevo PROFILE
        ##AUTH ADD [ACTIONS]
        def _add_configuration(self):
                profile=input("Please, insert the profile name :")
                url=input("Please, insert the caldera url:")
                key=input("Please, insert the caldera API-KEY:")
                config = ConfigParser()
                config.read(self.caldera_config_dir + self.caldera_config_file)
                profilelist=config.get('PROFILES', 'profilelist').split(',')
                selectePro=config.get('PROFILES', 'selectedprofile')
                profilelist.append(profile)
                config['PROFILES']={'profilelist':','.join(profilelist),'selectedprofile':selectePro}
                config[profile]={"url":url,"key":key}
                with open(self.caldera_config_dir + self.caldera_config_file, 'w') as configfile:
                        config.write(configfile)

        #Permite el cambio entre los diferentes PROFILES
        ##AUTH SWITCH [ACTIONS]
        def _switch_configuration(self,profile):
                config = ConfigParser()
                config.read(self.caldera_config_dir + self.caldera_config_file)
                if profile in config['PROFILES']['profilelist'].split(','):
                        config['PROFILES']['selectedprofile']=profile
                        with open(self.caldera_config_dir + self.caldera_config_file, 'w') as configfile:
                                config.write(configfile)
                else:
                        print('ERROR: {} do not exist!'.format(profile))

        #Inicia la configuración de la ruta de caldera | Permite añadir un nuevo PROFILE y lo inicia por default
        ##AUTH INIT [ACTIONS]
        def _init_configuration(self):
                profile=input("Please, insert the profile name :")
                url=input("Please, insert the caldera url:")
                key=input("Please, insert the caldera API-KEY:")
                config = ConfigParser()
                #ERROR_TO_SOLVE
                #config['PROFILES']={'profilelist':profile}
                config['PROFILES']={'profilelist':profile,'selectedprofile':profile}
                config[profile]={"url":url,"key":key}
                if not path.exists(self.caldera_config_dir):
                        makedirs(self.caldera_config_dir)
                with open(self.caldera_config_dir + self.caldera_config_file, 'w') as configfile:
                        config.write(configfile)
                self.caldera_selected_profile=profile

        #Guarda el estado de los PROFILES
        def _save_state(self):
                url,key=self._getConnection()

                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.get(url + '/api/save_state',headers=headers,verify=False)

                print (r.text)

        # Recupera la init_configuration de caldera | Nos permite llevar a cabo toda las peticiones en el script
        def _getConnection(self):
                config=ConfigParser()
                config.read(self.caldera_config_dir + self.caldera_config_file)
                selectedprofile=config['PROFILES']['selectedprofile']
                return config[selectedprofile]["url"], config[selectedprofile]["key"]




        def _access_run(self,id,paw):
                data={"paw":paw,"ability_id":id,"obfuscator":"plain-text"}
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}

                r = requests.post(url + '/plugin/access/exploit',headers=headers,json=data,verify=False)

                self._access_get(paw)



        def _access_get(self,paw):
                url,key=self._getConnection()
                fields={'host':'{:25}','group':'{:5}','username':'{:25}','paw':'{:5}','platform':'{:8}','contact':'{:7}','executors':'{:10}','privilege':'{:10}','trusted':'{:5}','last_seen':'{:20}'}
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                data_agent={"index":"agents","paw":paw}


                r_agent = requests.post(url + '/api/v2' ,headers=headers,json=data_agent,verify=False)
                agent=r_agent.json()[0]
                print('\t'.join(fields[field].format(field) for field in fields.keys()))
                print('\t'.join(fields[field].format(str(agent[field])) for field in fields.keys()))
                print('|_ {:40}\t{:10}\t{:40}\t{:15}\t{:20}\t{:20}\t{:10}'.format('ability_id','link_id','ability name','technique id','collect','finish','status'))
                for link in agent['links']:
                        link_id= int(link["id"])
                        ab_id = link['ability']['ability_id']
                        ab_name = link['ability']['name']
                        tech_id = link['ability']['technique_id']
                        if  link['collect'] ==None:
                                collect=""
                        else:
                                collect = link['collect']
                        if link['finish'] == None:
                                finish=""
                        else:
                                finish = link['finish']


                        if link['status']==0:
                                status=Fore.GREEN + 'success'
                        elif link['status']==-2:
                                status="discarted"
                        elif link['status']==1:
                                status=Fore.RED + 'failure'
                        elif link['status']==124:
                                status=Fore.BLUE +'timeout'
                        elif link['status']==-3 and collect == "":
                                status=Fore.YELLOW + 'collecting'
                        elif link['status']==-3 and collect != "":
                                status=Fore.LIGHTGREEN_EX + 'Running'
                        elif link['status']==-4:
                                status='untrusted'
                        elif link['status']==-5:
                                status='visibility'
                        else:
                                status='queued'

                        print ('|_ {:40}\t{:10}\t{:40}\t{:15}\t{:20}\t{:20}\t{:10}'.format(ab_id,link_id,ab_name,tech_id,collect,finish,status))
                        # data_result={"index":"result","link_id":link_id}
                        # r_result = requests.post(url + '/api/rest',headers=headers,json=data_result,verify=False)
                        # print('\t|\t')
                        # print('\t|\tCommand: {}'.format(base64.b64decode(link['command']).decode('utf-8')))
                        # print('\t|\tOutput:')
                        # if 'output' in r_result.json():
                        #       output=base64.b64decode(r_result.json()['output']).splitlines()

                        #       for line in output:
                        #               print('\t|\t{}'.format(line.decode('utf-8',errors='ignore')))

                        # else:
                        #       print('\t|\t{}'.format('No output returned'))
                        # print('\t|\t')

        def _command_run(self,paw,command):
                url,key=self._getConnection()
                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                ability_id=str(uuid4())

                ability={"index":"abilities",
                                "id":ability_id,
                                "name":"run_ability",
                                "description":"Ability use to launch customs commands to agents",
                                "tactic":"N/A","technique":{"attack_id":"N/A","name":"N/A"},
                                "platforms":{
                                        "linux":{"sh":{"command":command,"timeout":60}},
                                        "windows":{"psh":{"command":command,"timeout":60}}}}


                r = requests.put(url + '/api/v2',headers=headers,json=ability,verify=False)
                if r.status_code == 200:
                        run_data={"paw":paw,"ability_id":ability_id,"obfuscator":"plain-text"}
                        r = requests.post(url + '/plugin/access/exploit',headers=headers,json=run_data,verify=False)
                        if r.status_code == 200:
                                print("Command sent! - ",ability_id)
                                executed=False
                                while not executed:
                                        data_agent={"index":"agents","paw":paw}
                                        r_agent = requests.post(url + '/api/v2' ,headers=headers,json=data_agent,verify=False)
                                        agent=r_agent.json()[0]
                                        for link in agent['links']:
                                                if link['ability']['ability_id'] != ability_id:
                                                        pass
                                                else:
                                                        link_id= int(link["id"])
                                                        if  link['collect'] ==None:
                                                                collect=""

                                                        if link['status']==0:
                                                                status=Fore.GREEN + 'success'
                                                                executed=True
                                                                print("status:",status)
                                                                break
                                                        elif link['status']==-2:
                                                                status="discarted"
                                                                print("status:",status)
                                                                executed=True
                                                                break
                                                        elif link['status']==1:
                                                                status=Fore.RED + 'failure'
                                                                executed=True
                                                                print("status:",status)
                                                                break
                                                        elif link['status']==124:
                                                                status=Fore.BLUE +'timeout'
                                                                executed=True
                                                                print("status:",status)
                                                                break
                                                        elif link['status']==-3 and collect == "":
                                                                status=Fore.YELLOW + 'collecting'
                                                        elif link['status']==-3 and collect != "":
                                                                status=Fore.LIGHTGREEN_EX + 'Running'
                                                        elif link['status']==-4:
                                                                status='untrusted'
                                                                executed=True
                                                                break
                                                        elif link['status']==-5:
                                                                status='visibility'
                                                        else:
                                                                status='queued'

                                                        print("status:",status)
                                        time.sleep(5)

                                data_result={"index":"result","link_id":int(link_id)}
                                r_result = requests.post(url + '/api/v2',headers=headers,json=data_result,verify=False)

                                link = r_result.json()
                                print("Results:")
                                print("")
                                if link['output']:
                                        output=base64.b64decode(link['output']).splitlines()

                                        for line in output:
                                                print('\t{}'.format(line.decode('utf-8',errors='ignore')))

                                else:
                                        print('\t{}'.format('No output returned'))

                        else:
                                logging.error("Error al lanzar la ability %s", r.text)
                        data_delete ={"index":"abilities","ability_id":ability_id}
                        r_delete= requests.delete(url + '/api/v2',headers=headers,json=data_delete,verify=False)
                        if r_delete.status_code != 200:
                                print("Error al borrar la ability! %s ",r_delete.text)
                else:
                        print("Error al crear la ability %s", r.text)


        def _report(self, id):
                #ability_name,ability_id,technique_id,adversary_name,cleanup,command,payload,platform,executors
                data={"index":"adversaries","adversary_id":id}
                url,key=self._getConnection()

                headers={'KEY':key,'content-typer':'application/json; charset=utf8'}
                r = requests.post(url + '/api/v2',headers=headers,json=data,verify=False)


                for adv in r.json():
                        for ab in adv['atomic_ordering']:
                                command= base64.b64decode(ab['test']).decode('utf-8')
                                if len(ab['cleanup']) >0:
                                        cleanup=base64.b64decode(ab['cleanup'][0]).decode('utf-8')
                                else:
                                        cleanup=''
                                if len(ab['payloads'])>0:
                                        payloads = ' '.join(p for p in ab['payloads'])
                                else:
                                        payloads=''

                                print('\t'.join(field for field in [ab['name'],ab['ability_id'],ab['technique_id'],adv['name'],cleanup,command,payloads,ab['platform'],ab['executors']]))

##EXECUTE MAIN CLASS
if __name__ == '__main__':
        Calderactl()

