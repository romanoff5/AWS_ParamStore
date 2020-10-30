#!/bin/bash
pip freeze | grep "boto3\|botocore" >requirements.txt
