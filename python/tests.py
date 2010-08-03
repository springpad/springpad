#!/usr/bin/env python
# encoding: utf-8
"""
tests.py

Created by Pete Aykroyd on 2010-06-23.
Copyright (c) 2010 Spring Partners. All rights reserved.
"""

import sys, os, json, unittest, springpad
from springpad import SpringRpcService, ResponseFormat
from datetime import datetime

def slurp(filename):
    """returns a file as a string"""
    f = open(filename, 'r')
    contents = f.readlines()
    f.close()
    return ''.join(contents)

class TestFetcher:
    """mocked version of the fetcher"""
    def __init__(self):
        pass
        
    def create_next_test(self, response_path):
        """takes the path to the next response file"""
        self.response = slurp(response_path)
    
    def fetch(self, url, parameters=None, post_data=None, headers={}, method='GET'):
        return self.response

class SpringApiTestCase(unittest.TestCase):
    def setUp(self):
        self.rpc = SpringRpcService()
        self.fetcher = TestFetcher()
        self.rpc.fetcher = self.fetcher
        self.rpc.set_user_context('pete', "1e45abfe-4806-4b26-8463-565fbb19c0da")
        
    def tearDown(self):
        self.rpc = None
        self.fetcher = None
        springpad.get_block_store()._blocks={}
        
    def test_get_blocks(self):
        self.fetcher.create_next_test('test_files/blocks1.txt')
        blocks = self.rpc.get_blocks()

        self.assertEquals(len(blocks), 2)
        self.assertEquals(springpad.get_block_store().count(), 2)
        
        task = blocks[0]
        self.assertEquals(task.uuid, '1e3a0629-385a-49b8-8cc2-17a6d32a241f')
        self.assertEquals(task.name, 'Do taxes')
        self.assertEquals(task.type, 'Task')
        self.assertTrue(isinstance(task.created, datetime))
        self.assertTrue(isinstance(task.modified, datetime))
        
        task = blocks[1]
        dueDate = task.get('date')
        self.assertTrue(isinstance(dueDate, datetime))
        self.assertEquals(dueDate, datetime.strptime('6/24/10', '%m/%d/%y'))
        
    def test_mutator_set(self):
        self.fetcher.create_next_test('test_files/blocks1.txt')
        blocks = self.rpc.get_blocks()
        
        task= blocks[1]
        t = self.rpc.get_mutator()
        t.set(task, 'date', datetime.strptime('3/28/11', '%m/%d/%y'))
        
        self.assertEquals(len(t.commands), 1)
        cmd = t.commands[0]
        self.assertEquals(len(cmd), 4)
        self.assertEquals(cmd[0], 'set')
        self.assertEquals(cmd[1], '/UUID(1e392601-cbbd-4f90-b07b-72f93cfdcab1)/')
        self.assertEquals(cmd[2], 'date')
        datestring = cmd[3]
        self.assertTrue(datestring.startswith('/Date('))
        d = springpad.parse_date(datestring)
        self.assertEquals(d, datetime.strptime('3/28/11', '%m/%d/%y'))
        self.assertEquals(task.get('date'), datetime.strptime('3/28/11', '%m/%d/%y'))

    def test_block_references(self):
        self.fetcher.create_next_test('test_files/ref1.txt')
        blocks = self.rpc.get_blocks()
        
        self.assertEquals(springpad.get_block_store().count(), 3)
        
        person = springpad.get_block_store().get_block('1e36fc8b-fa11-414e-b571-7f3c08f325c1')
        self.assertEquals(person.name, 'John Smith')
        self.assertEquals(person.get('title'), 'Engineer')
        
        self.assertTrue(isinstance(blocks[0].blockMap['properties']['assignee'], springpad.BlockReference))
        self.assertEquals(blocks[0].get('assignee'), person)
        self.assertEquals(blocks[1].get('assignee'), person)

        self.fetcher.create_next_test('test_files/ref2.txt')
        blocks2 = self.rpc.get_blocks()
        
        self.assertEquals(person.get('title'), 'Senior Engineer')
        self.assertEquals(blocks2[0], blocks[0])

        self.fetcher.create_next_test('test_files/ref3.js')
        cafe = self.rpc.get_blocks()[0]
        
        self.assertEquals(cafe.get('contactInfo')[0].get('state'), 'MA')
        self.assertTrue(isinstance(cafe.blockMap['properties']['contactInfo'][0], springpad.BlockReference))
        
    def test_mutator_add(self):
        self.fetcher.create_next_test('test_files/block_mods.txt')
        tasklist, testtype = self.rpc.get_blocks()
        
        tasks = tasklist.get('tasks')
        self.assertEquals(len(tasks), 4)
        
        for task in tasks:
            self.assertEquals(task.type, 'Task')
            
        t = self.rpc.get_mutator()
        task = t.create('Task')
        t.set(task, 'name', 'E')
        t.add(tasklist, 'tasks', task)
        
        self.assertEquals(task.name, 'E')
        self.assertTrue(task.uuid.startswith('1e3'))
        self.assertEquals(len(tasklist.get('tasks')), 5)
        
        self.assertEquals(len(t.commands), 3)
        
        self.assertEquals(t.commands[0][0], 'create')
        self.assertEquals(t.commands[0][1], 'Task')
        self.assertEquals(t.commands[0][2], "/UUID(%s)/" % task.uuid)
        
        self.assertEquals(t.commands[1][0], 'set')
        self.assertEquals(t.commands[1][1], "/UUID(%s)/" % task.uuid)
        self.assertEquals(t.commands[1][2], 'name')
        self.assertEquals(t.commands[1][3], 'E')
        
        self.assertEquals(t.commands[2][0], 'add')
        self.assertEquals(t.commands[2][1], "/UUID(%s)/" % tasklist.uuid)
        self.assertEquals(t.commands[2][2], 'tasks')
        self.assertEquals(t.commands[2][3], "/UUID(%s)/" % task.uuid)
        
        t.commit()
        
        t = self.rpc.get_mutator()
        
        t.add(testtype, 'numbers', 42)
        t.add(testtype, 'strings', 'fish')
        
        self.assertEquals(t.commands[0][0], 'add')
        self.assertEquals(t.commands[0][1], "/UUID(%s)/" % testtype.uuid)
        self.assertEquals(t.commands[0][2], 'numbers')
        self.assertEquals(t.commands[0][3], 42)
        
        self.assertEquals(t.commands[1][0], 'add')
        self.assertEquals(t.commands[1][1], "/UUID(%s)/" % testtype.uuid)
        self.assertEquals(t.commands[1][2], 'strings')
        self.assertEquals(t.commands[1][3], 'fish')
        
    def test_mutator_remove(self):
        self.fetcher.create_next_test('test_files/block_mods.txt')
        tasklist, testtype = self.rpc.get_blocks()

        t = self.rpc.get_mutator()
        task = tasklist.get('tasks')[1]
        t.remove(tasklist, 'tasks', task)
        t.remove(testtype, 'numbers', 5)
        t.remove(testtype, 'strings', 'a')
        
        self.assertEquals(t.commands[0][0], 'remove')
        self.assertEquals(t.commands[0][1], "/UUID(%s)/" % tasklist.uuid)
        self.assertEquals(t.commands[0][2], 'tasks')
        self.assertEquals(t.commands[0][3], "/UUID(%s)/" % task.uuid)
        
        self.assertEquals(t.commands[1][0], 'remove')
        self.assertEquals(t.commands[1][1], "/UUID(%s)/" % testtype.uuid)
        self.assertEquals(t.commands[1][2], 'numbers')
        self.assertEquals(t.commands[1][3], 5)
        
        self.assertEquals(t.commands[2][0], 'remove')
        self.assertEquals(t.commands[2][1], "/UUID(%s)/" % testtype.uuid)
        self.assertEquals(t.commands[2][2], 'strings')
        self.assertEquals(t.commands[2][3], 'a')
                        
        self.assertEquals(len(tasklist.get('tasks')), 3)
        self.assertEquals(len(testtype.get('numbers')), 4)
        self.assertEquals(len(testtype.get('strings')), 2)
        
    def test_mutator_move(self):
        self.fetcher.create_next_test('test_files/block_mods.txt')
        tasklist, testtype = self.rpc.get_blocks()

        t = self.rpc.get_mutator()
        task = tasklist.get('tasks')[1]
        t.move(tasklist, 'tasks', task, 0)
        t.move(testtype, 'numbers', 5, 2)
        t.move(testtype, 'strings', 'a', 2)

        self.assertEquals(t.commands[0][0], 'move')
        self.assertEquals(t.commands[0][1], "/UUID(%s)/" % tasklist.uuid)
        self.assertEquals(t.commands[0][2], 'tasks')
        self.assertEquals(t.commands[0][3], "/UUID(%s)/" % task.uuid)
        self.assertEquals(t.commands[0][4], 0)

        self.assertEquals(t.commands[1][0], 'move')
        self.assertEquals(t.commands[1][1], "/UUID(%s)/" % testtype.uuid)
        self.assertEquals(t.commands[1][2], 'numbers')
        self.assertEquals(t.commands[1][3], 5)
        self.assertEquals(t.commands[1][4], 2)

        self.assertEquals(t.commands[2][0], 'move')
        self.assertEquals(t.commands[2][1], "/UUID(%s)/" % testtype.uuid)
        self.assertEquals(t.commands[2][2], 'strings')
        self.assertEquals(t.commands[2][3], 'a')
        self.assertEquals(t.commands[2][4], 2)

        self.assertEquals(map(lambda b: b.name, tasklist.get('tasks')), ['B', 'A', 'C', 'D'])
        self.assertEquals(testtype.get('numbers'), [1, 2, 5, 3, 4])
        self.assertEquals(testtype.get('strings'), ['b', 'c', 'a'])
 
    def test_mutator_delete(self):
        self.fetcher.create_next_test('test_files/block_mods.txt')
        tasklist, testtype = self.rpc.get_blocks()

        t = self.rpc.get_mutator()
        task = tasklist.get('tasks')[1]
        t.delete(task)

        self.assertEquals(t.commands[0][0], 'delete')
        self.assertEquals(t.commands[0][1], "/UUID(%s)/" % task.uuid)

    def test_response_format(self):
        self.fetcher.create_next_test('test_files/block_mods.txt')
        raw = self.rpc.get_blocks(resp_format=ResponseFormat.RawHtml)
        self.assertTrue(isinstance(raw, str))
        
        json = self.rpc.get_blocks(resp_format=ResponseFormat.Json)
        self.assertTrue(isinstance(json, list))
        self.assertTrue(isinstance(json[0], dict))

        b1, b2 = self.rpc.get_blocks(resp_format=ResponseFormat.Blocks)
        self.assertTrue(isinstance(b1, springpad.Block))

    def test_search_blocks(self):
        self.fetcher.create_next_test('test_files/search.js')
        blocks = self.rpc.find_new_blocks(type_filter='Book', text='lisp')
        
        self.assertEquals(len(blocks), 3)
        
        book = blocks[0]
        self.assertEquals(book.creatorUsername, "torvald")
        self.assertEquals(book.name, "Practical Common Lisp")
        self.assertEquals(book.get('author'), "Peter Seibel")

        # neither of these blocks should make it into the block store because they are not our blocks
        self.assertEquals(springpad.get_block_store().count(), 0)

        cafe = blocks[2]
        self.assertEquals(cafe.type, "Restaurant")
        self.assertTrue(isinstance(cafe.blockMap['properties']['contactInfo'][0], springpad.Block))
        self.assertEquals(cafe.get('contactInfo')[0].get('state'), 'MA')

if __name__ == '__main__':
    print 'Testing Springpad Python API Library'
    unittest.main()
