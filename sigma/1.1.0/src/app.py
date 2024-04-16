import os
import socket
import asyncio
import time
import random
import json
import subprocess
import yaml
from yaml import SafeLoader

from walkoff_app_sdk.app_base import AppBase

# Make file sample with namespace yara:
## curl http://localhost:5001/api/v1/files/create -H "Authorization: Bearer 09627dcb-7e2a-4843-819b-417d268ff840" -d '{"filename": "HelloWorld.yml", "org_id": "11f67b76-6051-4425-b0d6-be23daac6d12", "workflow_id": "global", "namespace": "sigma"}'

# 1. Generate the api.yaml based on downloaded files
# 2. Add a way to choose the rule and the target platform for it
# 3. Add the possibility of translating rules back and forth

# 4. Make it so you can start with Mitre Att&ck techniques 
# and automatically get the right rules set up with your tools :O
class Sigma(AppBase):
    __version__ = "1.1.0"
    app_name = "Sigma"  # this needs to match "name" in api.yaml

    def __init__(self, redis, logger, console_logger=None):
        """
        Each app should have this __init__ to set up Redis and logging.
        :param redis:
        :param logger:
        :param console_logger:
        """
        super().__init__(redis, logger, console_logger)

    def convert_yaml_to_json(self, shuffle_category):
        files = self.get_file_namespace(shuffle_category)
        self.logger.info(f"Files: {files}")

        basedir = "rules"
        os.mkdir(basedir)
        for member in files.namelist():
            filename = os.path.basename(member)
            if not filename:
                continue

            self.logger.info("File: %s" % member)
            source = files.open(member)
            with open("%s/%s" % (basedir, source.name), "wb+") as tmp:
                filedata = source.read()
                self.logger.info("Filedata (%s): %s" % (source.name, filedata))        
                dict=yaml.load(filedata, Loader=SafeLoader)
                self.logger.info("YAML: %s" % dict)
                json_file=json.dumps(dict)
                self.logger.info("Json_file :" % json_file)
                print(json_file)
    
    def get_searches(self, backend, pipeline, shuffle_category):
        files = self.get_file_namespace(shuffle_category)
        self.logger.info(f"Files: {files}")

        # This part should be in the SDK
        basedir = "rules"
        os.mkdir(basedir)
        for member in files.namelist():
            filename = os.path.basename(member)
            if not filename:
                continue

            self.logger.info("File: %s" % member)
            source = files.open(member)
            with open("%s/%s" % (basedir, source.name), "wb+") as tmp:
                filedata = source.read()
                self.logger.info("Filedata (%s): %s" % (source.name, filedata))
                tmp.write(filedata)
        
        self.logger.info(f"Dir: {os.listdir(basedir)}")

        rule = shuffle_category
        #filename = "file.yaml" 
        #with open(filename, "w+") as tmp:
        #    tmp.write(rule)
    
        code = "sigma convert -t %s" % backend
        #if len(pipeline) > 0:
        if pipeline:
            if "list" in pipeline:
                code += "--list"
            else:
                code += " -p %s" % pipeline
    
        code += " rules/*" 
        self.logger.info("Code: ", code)
        #json_code=json_loads(code)
        #print json_dumps(code)
        print(code)
        print()
        process = subprocess.Popen(
            code,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,  # nosec
        )
        stdout = process.communicate()
        self.logger.info("Stdout : %s" % stdout)
        item = ""
        if len(stdout[0]) > 0:
            print("Succesfully ran bash!")
            item = stdout[0]
        else:
            print("FAILED to run bash: ", stdout[1])
            item = stdout[1]
    
        try:
            ret = item.decode("utf-8")
            self.logger.info("Ret : %s", % ret)
            return ret
        except Exception:
            return item
    
        return item

if __name__ == "__main__":
    Sigma.run()
