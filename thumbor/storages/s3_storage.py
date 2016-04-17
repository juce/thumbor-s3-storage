#!/usr/bin/python
# -*- coding: utf-8 -*-

from thumbor.storages import BaseStorage
from tornado.concurrent import return_future

from boto.s3.connection import S3Connection
from boto.s3.key import Key


class Storage(BaseStorage):

    def put(self, path, bytes):
        aws_access_key_id = self.context.config.S3_ACCESS_KEY_ID
        aws_secret_access_key = self.context.config.S3_SECRET_ACCESS_KEY
        conn = S3Connection(aws_access_key_id, aws_secret_access_key)

        bucket = conn.get_bucket(self.context.config.S3_BUCKET)
        k = Key(bucket)

        k.key = path
        k.set_contents_from_string(bytes)
        bucket.set_acl('public-read', k.key)
        return path

    def put_crypto(self, path):
        return path

    def put_detector_data(self, path, data):
        return path

    @return_future
    def get_crypto(self, path, callback):
        callback(None)

    @return_future
    def get_detector_data(self, path, callback):
        callback(None)

    @return_future
    def get(self, path, callback):
        aws_access_key_id = self.context.config.S3_ACCESS_KEY_ID
        aws_secret_access_key = self.context.config.S3_SECRET_ACCESS_KEY
        conn = S3Connection(aws_access_key_id, aws_secret_access_key)

        bucket = conn.get_bucket(self.context.config.S3_BUCKET)
        k = Key(bucket)

        k.key = path
        bytes = k.get_contents_as_string()
        callback(bytes)

    @return_future
    def exists(self, path, callback):
        callback(False)

    def remove(self, path):
        aws_access_key_id = self.context.config.S3_ACCESS_KEY_ID
        aws_secret_access_key = self.context.config.S3_SECRET_ACCESS_KEY
        conn = S3Connection(aws_access_key_id, aws_secret_access_key)

        bucket = conn.get_bucket(self.context.config.S3_BUCKET)
        k = Key(bucket)

        k.key = path
        k.delete()
