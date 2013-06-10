from . import config

'''
info.py -  vFeed - Open Source Cross-linked and Aggregated Local Vulnerability Database

Class vFeedInfo : supplying the vFeed information
'''


class vFeedInfo(object):
    def __init__(self):
        self.vFeedInfo = {}

    def get_version(self):
        self.vFeedInfo['title'] = config.product['__title__']
        self.vFeedInfo['build'] = config.product['__build__']
        return self.vFeedInfo

    def get_owner(self):

        self.vFeedInfo['author'] = config.author['__name__']
        self.vFeedInfo['email'] = config.author['__email__']
        self.vFeedInfo['website'] = config.author['__website__']
        return self.vFeedInfo

    def get_config(self):

        self.vFeedInfo['primary'] = config.database['primary']
        self.vFeedInfo['secondary'] = config.database['secondary']
        return self.vFeedInfo