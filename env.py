import os
import pprint

def application(env, start_response):
    start_response('200 OK', [('Content-Type','text/plain')])
    return [pprint.pformat(env)]
    #return [repr(env)]
    #return [bytes(repr(os.environ), 'utf-8')]
    #return [repr(os.environ)]
    #return ["Hello World"]
