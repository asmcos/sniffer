# use SqlAlchemy

from sqlalchemy import create_engine,ForeignKey
from sqlalchemy.orm import sessionmaker,relationship
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import  String,Column,Integer,DateTime
import datetime
engine = create_engine("mysql+mysqldb://cpython:cpython.org@localhost:3306/httpdump")

Session = sessionmaker(bind=engine)
ses = Session()
ses.autocommit == True
Base = declarative_base()

class RequestTable(Base):
    __tablename__ = "request_tables" 
    id = Column(Integer, primary_key=True)
    created_at  = Column(DateTime, default=datetime.datetime.utcnow)
    first_line  = Column(String)
    is_resp     = Column(Integer)
    status_code = Column(Integer)
    request_uri = Column(String)
    host        = Column(String)
    src_ip      = Column(String)
    src_port    = Column(String)
    dst_ip      = Column(String)
    dst_port    = Column(String)
    def serialize(self):
        return {
            'ID': self.id, 
            'CreatedAt': self.created_at,
            'FirstLine': self.first_line,
            'StatusCode':self.status_code,
            'Host':self.host,
            'RequestURI':self.request_uri,
            'SrcIp':self.src_ip,
        }

class ResponseTable(Base):
    __tablename__ = "response_tables"
    id = Column(Integer, primary_key=True)
    created_at    = Column(DateTime, default=datetime.datetime.utcnow)
    request_refer = Column(Integer, ForeignKey("request_tables.id"))  
    first_line    = Column(String)
    status_code   = Column(Integer)
    src_ip      = Column(String)
    src_port    = Column(String)
    dst_ip      = Column(String)
    dst_port    = Column(String)
    
def insert_request(first_line,host,request_uri,src_ip,src_port,dst_ip,dst_port):
    req1 = RequestTable(first_line=first_line,
            host=host,
            request_uri=request_uri,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            is_resp = '0')
    ses.add(req1)
    ses.commit()

def insert_response(src_ip,src_port,dst_ip,dst_port,status_code):
    req1 = ses.query(RequestTable).filter(RequestTable.src_ip==dst_ip,
            RequestTable.src_port==dst_port,
            RequestTable.dst_ip==src_ip,
            RequestTable.dst_port==src_port,
            RequestTable.is_resp=='0').update({'is_resp':'1',
                'status_code':status_code})
    ses.commit()

def get_requests(offset,limit):
    ses1 = Session()
    reqs = ses1.query(RequestTable) \
        .order_by(RequestTable.id.desc())\
        .limit(limit)\
        .offset(offset).all()
    return [r.serialize() for r in reqs]

