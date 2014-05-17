#!/usr/bin/env python
"""
Copyright (c) 2010 HomeAway, Inc.
All rights reserved.  http://www.homeaway.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import logging
import logging.handlers

log_format = logging.Formatter('%(asctime)s %(name)s %(levelname)8s %(message)s')

def setup_logger(logfile=None, loglevel=logging.INFO):
    if logfile is not None:
        loghandler = logging.handlers.WatchedFileHandler( logfile )
        loghandler.setFormatter( log_format )
        loghandler.setLevel( loglevel )
        logging.getLogger().addHandler( loghandler )

    logging.getLogger().setLevel( loglevel )

def get_logger(name=None):
    if name is not None:
        return logging.getLogger( name )
    return logging.getLogger()

# vim: expandtab sw=4 ts=4 ai
