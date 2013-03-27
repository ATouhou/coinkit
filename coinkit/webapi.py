import simplejson
import urllib2

class WebApi(object):

    @classmethod
    def balance_bci(cls, address):
        h = urllib2.urlopen('http://blockchain.info/rawaddr/%s' % address)
        json = simplejson.load(h)
        h.close()
        f = float(json['final_balance'])/100000000
        return f

    @classmethod
    def balance_bec(cls, address):
        h = urllib2.urlopen('http://blockexplorer.com/q/addressbalance/%s' % address)
        f = float(h.read())
        h.close()
        return f

    @classmethod
    def fullbalance_bci(cls, address):
        h = urllib2.urlopen('http://blockchain.info/rawaddr/%s' % address)
        json = simplejson.load(h)
        h.close()
        r = float(json['total_received'])/100000000
        s = -float(json['total_sent'])/100000000
        f = float(json['final_balance'])/100000000
        return (f, r, s)

    @classmethod
    def fullbalance_bec(cls, address):
        h = urllib2.urlopen('http://blockexplorer.com/q/getreceivedbyaddress/%s' % address)
        r = float(h.read())
        h.close()
        h = urllib2.urlopen('http://blockexplorer.com/q/getsentbyaddress/%s' % address)
        s = -float(h.read())
        h.close()
        h = urllib2.urlopen('http://blockexplorer.com/q/addressbalance/%s' % address)
        f = float(h.read())
        h.close()
        return (f, r, s)
