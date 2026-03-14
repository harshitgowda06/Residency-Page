/*
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║   Residence Management System  —  C++ Single-File Backend       ║
 * ╠══════════════════════════════════════════════════════════════════╣
 * ║  Build:  g++ -std=c++17 -O2 -o residence main.cpp -lpthread     ║
 * ║          -lpq                                                    ║
 * ║  Run:    DATABASE_URL=<postgres-url> ./residence 3000            ║
 * ║  Open:   http://localhost:3000                                   ║
 * ║                                                                  ║
 * ║  Default admin  →  username: admin   password: admin123         ║
 * ║  Residents self-register with name + room number + password     ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 *  Dependencies: libpq (PostgreSQL C client), pthreads
 */

// ─── system headers ───────────────────────────────────────────────
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <signal.h>
#include <libpq-fe.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// ─── C++ headers ──────────────────────────────────────────────────
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// ═══════════════════════════════════════════════════════════════════
//  §1  SHA-256  (pure C++ — no OpenSSL needed)
// ═══════════════════════════════════════════════════════════════════
namespace SHA256Impl {
    static const uint32_t K[64]={
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    inline uint32_t rotr(uint32_t x,int n){ return (x>>n)|(x<<(32-n)); }

    std::string hash(const std::string& msg){
        uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
        uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
        std::vector<uint8_t> data(msg.begin(),msg.end());
        uint64_t bitlen=data.size()*8;
        data.push_back(0x80);
        while(data.size()%64!=56) data.push_back(0);
        for(int i=7;i>=0;i--) data.push_back((bitlen>>(i*8))&0xFF);
        for(size_t chunk=0;chunk<data.size();chunk+=64){
            uint32_t w[64]={};
            for(int i=0;i<16;i++)
                w[i]=(uint32_t(data[chunk+i*4])<<24)|(uint32_t(data[chunk+i*4+1])<<16)
                    |(uint32_t(data[chunk+i*4+2])<<8)|data[chunk+i*4+3];
            for(int i=16;i<64;i++){
                uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
                uint32_t s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
                w[i]=w[i-16]+s0+w[i-7]+s1;
            }
            uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
            for(int i=0;i<64;i++){
                uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25);
                uint32_t ch=(e&f)^(~e&g);
                uint32_t t1=h+S1+ch+K[i]+w[i];
                uint32_t S0=rotr(a,2)^rotr(a,13)^rotr(a,22);
                uint32_t maj=(a&b)^(a&c)^(b&c);
                uint32_t t2=S0+maj;
                h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
            }
            h0+=a;h1+=b;h2+=c;h3+=d;h4+=e;h5+=f;h6+=g;h7+=h;
        }
        std::ostringstream o;
        for(auto v:{h0,h1,h2,h3,h4,h5,h6,h7})
            o<<std::hex<<std::setw(8)<<std::setfill('0')<<v;
        return o.str();
    }
} // namespace SHA256Impl

// ═══════════════════════════════════════════════════════════════════
//  §2  Utilities
// ═══════════════════════════════════════════════════════════════════
static std::string randomHex(int bytes){
    std::random_device rd;
    std::string out; out.reserve(bytes*2);
    for(int i=0;i<bytes;i++){
        char buf[3]; snprintf(buf,sizeof(buf),"%02x",rd()&0xFF);
        out+=buf;
    }
    return out;
}

static std::string makeUID(){
    static std::atomic<uint64_t> cnt{0};
    auto ns=std::chrono::system_clock::now().time_since_epoch().count();
    std::ostringstream o;
    o<<std::hex<<ns<<std::hex<<++cnt;
    return o.str();
}

static std::string hashPw(const std::string& pw, const std::string& salt){
    // iterated SHA-256 key stretching (10 000 rounds)
    std::string h=salt+pw;
    for(int i=0;i<10000;i++) h=SHA256Impl::hash(h+std::to_string(i));
    return h;
}

static std::string todayStr(){
    std::time_t t=std::time(nullptr);
    std::tm tm=*std::localtime(&t);
    char buf[16]; std::strftime(buf,sizeof(buf),"%Y-%m-%d",&tm);
    return buf;
}
static std::string nowISO(){
    std::time_t t=std::time(nullptr);
    std::tm tm=*std::localtime(&t);
    char buf[32]; std::strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",&tm);
    return buf;
}
static std::string dateOffset(int days){
    std::time_t t=std::time(nullptr)+(std::time_t)days*86400;
    std::tm tm=*std::localtime(&t);
    char buf[16]; std::strftime(buf,sizeof(buf),"%Y-%m-%d",&tm);
    return buf;
}

static std::string toLower(std::string s){
    std::transform(s.begin(),s.end(),s.begin(),::tolower); return s;
}

// ═══════════════════════════════════════════════════════════════════
//  §3  JSON engine
// ═══════════════════════════════════════════════════════════════════
struct Json {
    enum Type { NUL,BOOL,NUM,STR,ARR,OBJ } type=NUL;
    bool b=false; double n=0; std::string s;
    std::vector<Json> arr;
    std::vector<std::pair<std::string,Json>> obj;

    Json(){}
    explicit Json(bool v):type(BOOL),b(v){}
    explicit Json(double v):type(NUM),n(v){}
    explicit Json(int v):type(NUM),n(v){}
    explicit Json(long long v):type(NUM),n((double)v){}
    explicit Json(const std::string& v):type(STR),s(v){}
    explicit Json(const char* v):type(STR),s(v){}
    static Json array() { Json j; j.type=ARR; return j; }
    static Json object(){ Json j; j.type=OBJ; return j; }

    Json& operator[](const std::string& k){
        for(auto&p:obj) if(p.first==k) return p.second;
        obj.push_back({k,Json()}); return obj.back().second;
    }
    const Json& operator[](const std::string& k) const {
        static Json nil; for(auto&p:obj) if(p.first==k) return p.second; return nil;
    }
    bool        has(const std::string& k) const { for(auto&p:obj) if(p.first==k) return true; return false; }
    void        set(const std::string& k, Json v){ (*this)[k]=std::move(v); }
    void        push(Json v){ arr.push_back(std::move(v)); }
    bool        asBool()   const { return b; }
    double      asNum()    const { return n; }
    long long   asInt()    const { return (long long)n; }
    std::string asStr()    const { return s; }

    std::string dump(int ind=0, int cur=0) const {
        std::string pad(cur,' '), ipad(cur+ind,' ');
        std::ostringstream o;
        switch(type){
            case NUL: o<<"null"; break;
            case BOOL:o<<(b?"true":"false"); break;
            case NUM: if(n==(long long)n) o<<(long long)n; else o<<std::fixed<<std::setprecision(4)<<n; break;
            case STR: {
                o<<'"';
                for(char c:s){
                    if(c=='"') o<<"\\\"";
                    else if(c=='\\') o<<"\\\\";
                    else if(c=='\n') o<<"\\n";
                    else if(c=='\r') o<<"\\r";
                    else if(c=='\t') o<<"\\t";
                    else             o<<c;
                }
                o<<'"'; break;
            }
            case ARR: {
                o<<'[';
                for(size_t i=0;i<arr.size();i++){
                    if(ind) o<<'\n'<<ipad;
                    o<<arr[i].dump(ind,cur+ind);
                    if(i+1<arr.size()) o<<',';
                }
                if(ind&&!arr.empty()) o<<'\n'<<pad;
                o<<']'; break;
            }
            case OBJ: {
                o<<'{';
                for(size_t i=0;i<obj.size();i++){
                    if(ind) o<<'\n'<<ipad;
                    // write key
                    o<<'"'; for(char c:obj[i].first){ if(c=='"')o<<"\\\""; else o<<c; } o<<'"';
                    o<<':';
                    if(ind) o<<' ';
                    o<<obj[i].second.dump(ind,cur+ind);
                    if(i+1<obj.size()) o<<',';
                }
                if(ind&&!obj.empty()) o<<'\n'<<pad;
                o<<'}'; break;
            }
        }
        return o.str();
    }
};

struct JsonParser {
    const std::string& src; size_t pos=0;
    JsonParser(const std::string& s):src(s){}
    void ws(){ while(pos<src.size()&&isspace((unsigned char)src[pos])) pos++; }
    Json parse(){
        ws(); if(pos>=src.size()) return Json();
        char c=src[pos];
        if(c=='{') return parseObj();
        if(c=='[') return parseArr();
        if(c=='"') return parseStr();
        if(c=='t'){ pos+=4; return Json(true); }
        if(c=='f'){ pos+=5; return Json(false); }
        if(c=='n'){ pos+=4; return Json(); }
        return parseNum();
    }
    Json parseObj(){
        Json j=Json::object(); pos++; ws();
        if(pos<src.size()&&src[pos]=='}'){ pos++; return j; }
        while(pos<src.size()){
            ws(); auto k=parseStr().asStr(); ws(); pos++; ws();
            j.set(k,parse()); ws();
            if(pos<src.size()&&src[pos]==',') pos++;
            ws(); if(pos<src.size()&&src[pos]=='}'){ pos++; break; }
        }
        return j;
    }
    Json parseArr(){
        Json j=Json::array(); pos++; ws();
        if(pos<src.size()&&src[pos]==']'){ pos++; return j; }
        while(pos<src.size()){
            ws(); j.push(parse()); ws();
            if(pos<src.size()&&src[pos]==',') pos++;
            ws(); if(pos<src.size()&&src[pos]==']'){ pos++; break; }
        }
        return j;
    }
    Json parseStr(){
        pos++; std::string out;
        while(pos<src.size()&&src[pos]!='"'){
            if(src[pos]=='\\'){
                pos++; if(pos>=src.size()) break;
                char e=src[pos];
                if(e=='"')  out+='"';
                else if(e=='\\') out+='\\';
                else if(e=='n')  out+='\n';
                else if(e=='r')  out+='\r';
                else if(e=='t')  out+='\t';
                else out+=e;
            } else { out+=src[pos]; }
            pos++;
        }
        pos++; return Json(out);
    }
    Json parseNum(){
        size_t st=pos;
        if(pos<src.size()&&src[pos]=='-') pos++;
        while(pos<src.size()&&(isdigit((unsigned char)src[pos])||src[pos]=='.'
              ||src[pos]=='e'||src[pos]=='E'||src[pos]=='+'||src[pos]=='-')) pos++;
        try{ return Json(std::stod(src.substr(st,pos-st))); } catch(...){ return Json(); }
    }
};
static Json parseJson(const std::string& s){ JsonParser p(s); return p.parse(); }

// ═══════════════════════════════════════════════════════════════════
//  §4  Data models
// ═══════════════════════════════════════════════════════════════════
struct User      { std::string id,name,room,username,hash,salt,role,email,phone,createdAt; };
struct Notice    { std::string id,text; bool active=true,urgent=false; };
struct NewsItem  { std::string id,title,date,category,content; };
struct Event     {
    std::string id,name,date,time_,description,location,createdAt;
    int maxParticipants=20;
    std::vector<std::string> participants;
};
struct LaundryBk { std::string id,name,room,userId,machineId,date,slot,createdAt; };
struct EquipBk   { std::string id,name,room,userId,item,date,startTime,endTime,createdAt; int duration=60; };

// ═══════════════════════════════════════════════════════════════════
//  §5  JSON serialisers
// ═══════════════════════════════════════════════════════════════════
static Json toJ(const User& u){
    Json j=Json::object();
    j["id"]=Json(u.id); j["name"]=Json(u.name); j["room"]=Json(u.room);
    j["username"]=Json(u.username); j["role"]=Json(u.role);
    j["email"]=Json(u.email); j["phone"]=Json(u.phone);
    j["createdAt"]=Json(u.createdAt);
    return j;
}
static Json toJ(const Notice& n){
    Json j=Json::object();
    j["id"]=Json(n.id); j["text"]=Json(n.text); j["active"]=Json(n.active); j["urgent"]=Json(n.urgent);
    return j;
}
static Json toJ(const NewsItem& it){
    Json j=Json::object();
    j["id"]=Json(it.id); j["title"]=Json(it.title); j["date"]=Json(it.date);
    j["category"]=Json(it.category); j["content"]=Json(it.content);
    return j;
}
static Json toJ(const Event& e){
    Json j=Json::object();
    j["id"]=Json(e.id); j["name"]=Json(e.name); j["date"]=Json(e.date); j["time"]=Json(e.time_);
    j["description"]=Json(e.description); j["location"]=Json(e.location);
    j["maxParticipants"]=Json((long long)e.maxParticipants); j["createdAt"]=Json(e.createdAt);
    Json jp=Json::array(); for(auto& p:e.participants) jp.push(Json(p));
    j["participants"]=jp;
    return j;
}
static Json toJ(const LaundryBk& b){
    Json j=Json::object();
    j["id"]=Json(b.id); j["name"]=Json(b.name); j["room"]=Json(b.room);
    j["userId"]=Json(b.userId); j["machineId"]=Json(b.machineId);
    j["date"]=Json(b.date); j["slot"]=Json(b.slot); j["createdAt"]=Json(b.createdAt);
    return j;
}
static Json toJ(const EquipBk& b){
    Json j=Json::object();
    j["id"]=Json(b.id); j["name"]=Json(b.name); j["room"]=Json(b.room);
    j["userId"]=Json(b.userId); j["item"]=Json(b.item); j["date"]=Json(b.date);
    j["startTime"]=Json(b.startTime); j["endTime"]=Json(b.endTime);
    j["duration"]=Json((long long)b.duration); j["createdAt"]=Json(b.createdAt);
    return j;
}

template<typename T>
static Json toJArr(const std::vector<T>& v){
    Json arr=Json::array();
    for(auto& x:v) arr.push(toJ(x));
    return arr;
}

// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
//  §6  Database  (PostgreSQL-backed, in-memory cache)
// ═══════════════════════════════════════════════════════════════════

static std::string pgEsc(PGconn* c, const std::string& s){
    char* e=PQescapeLiteral(c,s.c_str(),s.size());
    if(!e) return "''";
    std::string r(e); PQfreemem(e); return r;
}
static std::string pgStr(PGresult* r,int row,int col){
    if(PQgetisnull(r,row,col)) return "";
    return PQgetvalue(r,row,col);
}
static bool pgBool(PGresult* r,int row,int col){
    auto v=pgStr(r,row,col);
    return v=="t"||v=="true"||v=="1";
}

class DB {
public:
    std::vector<User>      users;
    std::vector<Notice>    notices;
    std::vector<NewsItem>  news;
    std::vector<Event>     events;
    std::vector<LaundryBk> laundry;
    std::vector<EquipBk>   equip;
    std::mutex             mtx;
    PGconn*                pg_=nullptr;

    // ── find helpers ─────────────────────────────────────────────
    User*      findUser(const std::string& id)   { for(auto&u:users)   if(u.id==id)       return &u; return nullptr; }
    User*      findByUsername(const std::string& u){ for(auto&x:users) if(toLower(x.username)==toLower(u)) return &x; return nullptr; }
    User*      findByRoom(const std::string& r)  { for(auto&u:users)   if(u.role!="admin"&&toLower(u.room)==toLower(r)) return &u; return nullptr; }
    Event*     findEvent(const std::string& id)  { for(auto&e:events)  if(e.id==id)       return &e; return nullptr; }
    LaundryBk* findLaundry(const std::string& id){ for(auto&b:laundry) if(b.id==id)       return &b; return nullptr; }
    EquipBk*   findEquip(const std::string& id)  { for(auto&b:equip)   if(b.id==id)       return &b; return nullptr; }

    // ── PG exec helpers ──────────────────────────────────────────
    bool exec(const std::string& sql){
        PGresult* r=PQexec(pg_,sql.c_str());
        bool ok=(PQresultStatus(r)==PGRES_COMMAND_OK||PQresultStatus(r)==PGRES_TUPLES_OK);
        if(!ok) std::cerr<<"PG error: "<<PQerrorMessage(pg_)<<"\nSQL: "<<sql.substr(0,300)<<"\n";
        PQclear(r); return ok;
    }
    PGresult* query(const std::string& sql){
        PGresult* r=PQexec(pg_,sql.c_str());
        if(PQresultStatus(r)!=PGRES_TUPLES_OK)
            std::cerr<<"PG query error: "<<PQerrorMessage(pg_)<<"\n";
        return r;
    }

    // ── Schema creation ──────────────────────────────────────────
    void createSchema(){
        exec(R"(CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY, name TEXT, room TEXT, username TEXT UNIQUE,
            hash TEXT, salt TEXT, role TEXT, email TEXT, phone TEXT, created_at TEXT))");
        exec(R"(CREATE TABLE IF NOT EXISTS notices(
            id TEXT PRIMARY KEY, text TEXT, active BOOLEAN, urgent BOOLEAN))");
        exec(R"(CREATE TABLE IF NOT EXISTS news(
            id TEXT PRIMARY KEY, title TEXT, date TEXT, category TEXT, content TEXT))");
        exec(R"(CREATE TABLE IF NOT EXISTS events(
            id TEXT PRIMARY KEY, name TEXT, date TEXT, time_ TEXT,
            description TEXT, location TEXT, max_participants INT,
            participants TEXT, created_at TEXT))");
        exec(R"(CREATE TABLE IF NOT EXISTS laundry(
            id TEXT PRIMARY KEY, name TEXT, room TEXT, user_id TEXT,
            machine_id TEXT, date TEXT, slot TEXT, created_at TEXT))");
        exec(R"(CREATE TABLE IF NOT EXISTS equip(
            id TEXT PRIMARY KEY, name TEXT, room TEXT, user_id TEXT,
            item TEXT, date TEXT, start_time TEXT, end_time TEXT,
            duration INT, created_at TEXT))");
    }

    // ── Save: write entire in-memory state to PG ─────────────────
    void save(){
        // users
        exec("DELETE FROM users");
        for(auto&u:users){
            exec("INSERT INTO users VALUES("+pgEsc(pg_,u.id)+","+pgEsc(pg_,u.name)+","+
                 pgEsc(pg_,u.room)+","+pgEsc(pg_,u.username)+","+pgEsc(pg_,u.hash)+","+
                 pgEsc(pg_,u.salt)+","+pgEsc(pg_,u.role)+","+pgEsc(pg_,u.email)+","+
                 pgEsc(pg_,u.phone)+","+pgEsc(pg_,u.createdAt)+")");
        }
        // notices
        exec("DELETE FROM notices");
        for(auto&n:notices){
            std::string act=n.active?"true":"false", urg=n.urgent?"true":"false";
            exec("INSERT INTO notices VALUES("+pgEsc(pg_,n.id)+","+pgEsc(pg_,n.text)+","+act+","+urg+")");
        }
        // news
        exec("DELETE FROM news");
        for(auto&it:news){
            exec("INSERT INTO news VALUES("+pgEsc(pg_,it.id)+","+pgEsc(pg_,it.title)+","+
                 pgEsc(pg_,it.date)+","+pgEsc(pg_,it.category)+","+pgEsc(pg_,it.content)+")");
        }
        // events — participants stored as JSON array string
        exec("DELETE FROM events");
        for(auto&e:events){
            // build participants as comma-separated
            std::string parts="";
            for(size_t i=0;i<e.participants.size();i++){
                if(i) parts+="|";
                parts+=e.participants[i];
            }
            exec("INSERT INTO events VALUES("+pgEsc(pg_,e.id)+","+pgEsc(pg_,e.name)+","+
                 pgEsc(pg_,e.date)+","+pgEsc(pg_,e.time_)+","+pgEsc(pg_,e.description)+","+
                 pgEsc(pg_,e.location)+","+std::to_string(e.maxParticipants)+","+
                 pgEsc(pg_,parts)+","+pgEsc(pg_,e.createdAt)+")");
        }
        // laundry
        exec("DELETE FROM laundry");
        for(auto&b:laundry){
            exec("INSERT INTO laundry VALUES("+pgEsc(pg_,b.id)+","+pgEsc(pg_,b.name)+","+
                 pgEsc(pg_,b.room)+","+pgEsc(pg_,b.userId)+","+pgEsc(pg_,b.machineId)+","+
                 pgEsc(pg_,b.date)+","+pgEsc(pg_,b.slot)+","+pgEsc(pg_,b.createdAt)+")");
        }
        // equip
        exec("DELETE FROM equip");
        for(auto&b:equip){
            exec("INSERT INTO equip VALUES("+pgEsc(pg_,b.id)+","+pgEsc(pg_,b.name)+","+
                 pgEsc(pg_,b.room)+","+pgEsc(pg_,b.userId)+","+pgEsc(pg_,b.item)+","+
                 pgEsc(pg_,b.date)+","+pgEsc(pg_,b.startTime)+","+pgEsc(pg_,b.endTime)+","+
                 std::to_string(b.duration)+","+pgEsc(pg_,b.createdAt)+")");
        }
    }

    // ── Load: read from PG into memory ───────────────────────────
    void load(const std::string& dbUrl){
        pg_=PQconnectdb(dbUrl.c_str());
        if(PQstatus(pg_)!=CONNECTION_OK){
            std::cerr<<"PG connect failed: "<<PQerrorMessage(pg_)<<"\n";
            std::cerr<<"Falling back to in-memory (data won't persist)\n";
            pg_=nullptr; seed(); return;
        }
        std::cout<<"  PostgreSQL connected\n";
        createSchema();

        // users
        {auto* r=query("SELECT id,name,room,username,hash,salt,role,email,phone,created_at FROM users");
        for(int i=0;i<PQntuples(r);i++){
            User u; u.id=pgStr(r,i,0); u.name=pgStr(r,i,1); u.room=pgStr(r,i,2);
            u.username=pgStr(r,i,3); u.hash=pgStr(r,i,4); u.salt=pgStr(r,i,5);
            u.role=pgStr(r,i,6); u.email=pgStr(r,i,7); u.phone=pgStr(r,i,8);
            u.createdAt=pgStr(r,i,9);
            users.push_back(u);
        } PQclear(r);}

        // notices
        {auto* r=query("SELECT id,text,active,urgent FROM notices");
        for(int i=0;i<PQntuples(r);i++){
            Notice n; n.id=pgStr(r,i,0); n.text=pgStr(r,i,1);
            n.active=pgBool(r,i,2); n.urgent=pgBool(r,i,3);
            notices.push_back(n);
        } PQclear(r);}

        // news
        {auto* r=query("SELECT id,title,date,category,content FROM news ORDER BY date DESC");
        for(int i=0;i<PQntuples(r);i++){
            NewsItem it; it.id=pgStr(r,i,0); it.title=pgStr(r,i,1);
            it.date=pgStr(r,i,2); it.category=pgStr(r,i,3); it.content=pgStr(r,i,4);
            news.push_back(it);
        } PQclear(r);}

        // events
        {auto* r=query("SELECT id,name,date,time_,description,location,max_participants,participants,created_at FROM events ORDER BY date");
        for(int i=0;i<PQntuples(r);i++){
            Event e; e.id=pgStr(r,i,0); e.name=pgStr(r,i,1); e.date=pgStr(r,i,2);
            e.time_=pgStr(r,i,3); e.description=pgStr(r,i,4); e.location=pgStr(r,i,5);
            e.maxParticipants=std::stoi(pgStr(r,i,6).empty()?"20":pgStr(r,i,6));
            std::string parts=pgStr(r,i,7);
            if(!parts.empty()){
                std::istringstream ss(parts); std::string p;
                while(std::getline(ss,p,'|')) if(!p.empty()) e.participants.push_back(p);
            }
            e.createdAt=pgStr(r,i,8);
            events.push_back(e);
        } PQclear(r);}

        // laundry
        {auto* r=query("SELECT id,name,room,user_id,machine_id,date,slot,created_at FROM laundry");
        for(int i=0;i<PQntuples(r);i++){
            LaundryBk b; b.id=pgStr(r,i,0); b.name=pgStr(r,i,1); b.room=pgStr(r,i,2);
            b.userId=pgStr(r,i,3); b.machineId=pgStr(r,i,4);
            b.date=pgStr(r,i,5); b.slot=pgStr(r,i,6); b.createdAt=pgStr(r,i,7);
            laundry.push_back(b);
        } PQclear(r);}

        // equip
        {auto* r=query("SELECT id,name,room,user_id,item,date,start_time,end_time,duration,created_at FROM equip");
        for(int i=0;i<PQntuples(r);i++){
            EquipBk b; b.id=pgStr(r,i,0); b.name=pgStr(r,i,1); b.room=pgStr(r,i,2);
            b.userId=pgStr(r,i,3); b.item=pgStr(r,i,4); b.date=pgStr(r,i,5);
            b.startTime=pgStr(r,i,6); b.endTime=pgStr(r,i,7);
            b.duration=std::stoi(pgStr(r,i,8).empty()?"60":pgStr(r,i,8));
            b.createdAt=pgStr(r,i,9);
            equip.push_back(b);
        } PQclear(r);}

        ensureAdmin();
        std::cout<<"  Loaded "<<users.size()<<" users, "<<news.size()
                 <<" news, "<<events.size()<<" events\n";
    }

    void ensureAdmin(){
        if(findByUsername("admin")) return;
        User u; u.id=makeUID(); u.name="Management"; u.room="Admin"; u.username="admin";
        u.salt=randomHex(16); u.hash=hashPw("admin123",u.salt); u.role="admin"; u.createdAt=nowISO();
        users.push_back(u); save();
        std::cout<<"  Admin created  username=admin  password=admin123\n";
    }

    void seed(){
        ensureAdmin();
        auto td=todayStr();
        notices.push_back({makeUID(),"Welcome to the Residence Portal — news, events, and bookings in one place.",true,false});
        notices.push_back({makeUID(),"The vacuum cleaner is currently missing. Please report if found.",true,true});

        auto addN=[&](auto t,auto d,auto c,auto ct){ NewsItem it; it.id=makeUID(); it.title=t; it.date=d; it.category=c; it.content=ct; news.push_back(it); };
        addN("New Freezer Coming Soon",            td,"Kitchen",     "A third freezer is expected to arrive soon. More details will be shared once a delivery date is confirmed.");
        addN("Kitchen Lockers Installation",       td,"Kitchen",     "Lockers for the kitchen are expected soon, providing dedicated storage for each resident's supplies.");
        addN("Shelf & Drawer Allocation — Action Required",td,"Kitchen","Drawers and shelves are available inside the kitchen and in the lounge. Residents must identify their desired space and contact Mostafa to reserve it.");
        addN("Fridge Shelf System Now Active",     td,"Kitchen",     "Identified shelves inside the fridge are now in operation. All residents must keep their designated shelf clean at all times.");
        addN("Laundry Room Whiteboard Coming",     td,"Laundry",     "A whiteboard will be installed to improve communication. Residents will write their Name, Room Number, and Machine ID to track usage.");
        addN("10-Minute Rule Reminder",            td,"Laundry",     "The laundry room 10-minute rule remains in effect. If laundry sits in a machine for more than 10 minutes after the cycle ends, another resident may move it.");
        addN("Vacuum Cleaner Missing",             td,"Maintenance", "The shared vacuum is currently unaccounted for. If you have it or know its location, please return it or inform management immediately.");
        addN("Vacuum Usage Policy",                td,"Maintenance", "Vacuum use is limited to a maximum of 1 hour per day per resident. A booking system will be implemented shortly.");
        addN("Report Maintenance Issues",          td,"Maintenance", "Residents should report all maintenance issues promptly — broken lights, missing hangers, or any damage to shared spaces.");
        addN("Community Events Recap",             dateOffset(-14),"General","Previous community events had a strong positive impact. More events are being planned and will be announced soon.");

        auto addE=[&](auto nm,auto dt,auto tm,auto desc,auto loc,int mx,std::vector<std::string> parts={}){
            Event e; e.id=makeUID(); e.name=nm; e.date=dt; e.time_=tm; e.description=desc;
            e.location=loc; e.maxParticipants=mx; e.participants=parts; e.createdAt=td;
            events.push_back(e);
        };
        addE("Community Game Night",   dateOffset(7), "19:00","Join your neighbours for board games and card games. All skill levels welcome!","Lounge Area",15);
        addE("Shared Cooking Evening", dateOffset(14),"18:30","We cook together, we eat together. This month: Mediterranean food.","Kitchen",10);
        addE("Building Welcome Gathering",dateOffset(-7),"18:00","The first official welcome gathering for all current residents.","Lounge Area",20,{"Room 101","Room 102","Room 103","Room 104","Room 105"});

        if(pg_) save();
    }
};


// ═══════════════════════════════════════════════════════════════════
//  §7  Session store
// ═══════════════════════════════════════════════════════════════════
class Sessions {
    struct S{ std::string uid; long long exp; };
    std::unordered_map<std::string,S> store_;
    std::mutex mtx_;
    static const long long TTL=7LL*24*3600*1000; // 7 days ms
    long long nowMs(){ return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
public:
    std::string create(const std::string& uid){
        auto tok=randomHex(32);
        std::lock_guard<std::mutex> lk(mtx_);
        store_[tok]={uid,nowMs()+TTL};
        return tok;
    }
    std::string getUid(const std::string& tok){
        if(tok.empty()) return "";
        std::lock_guard<std::mutex> lk(mtx_);
        auto it=store_.find(tok);
        if(it==store_.end()) return "";
        if(nowMs()>it->second.exp){ store_.erase(it); return ""; }
        return it->second.uid;
    }
    void remove(const std::string& tok){
        std::lock_guard<std::mutex> lk(mtx_);
        store_.erase(tok);
    }
};

// ═══════════════════════════════════════════════════════════════════
//  §8  SSE broker  (Server-Sent Events for real-time push)
// ═══════════════════════════════════════════════════════════════════
class SSEBroker {
    std::set<int> fds_;
    std::mutex mtx_;
public:
    void add(int fd){ std::lock_guard<std::mutex> lk(mtx_); fds_.insert(fd); }
    void remove(int fd){ std::lock_guard<std::mutex> lk(mtx_); fds_.erase(fd); }
    void broadcast(const std::string& event, const std::string& data){
        std::string msg="event: "+event+"\ndata: "+data+"\n\n";
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<int> dead;
        for(int fd:fds_)
            if(::send(fd,msg.c_str(),msg.size(),MSG_NOSIGNAL)<=0) dead.push_back(fd);
        for(int fd:dead) fds_.erase(fd);
    }
};

// ═══════════════════════════════════════════════════════════════════
//  §9  HTTP layer
// ═══════════════════════════════════════════════════════════════════
struct Req {
    std::string method, path, body;
    std::unordered_map<std::string,std::string> headers;
    std::unordered_map<std::string,std::string> params;   // route :params
};
struct Res {
    int status=200;
    std::string statusText="OK";
    std::string body;
    std::unordered_map<std::string,std::string> headers;

    void json(const std::string& j){ headers["Content-Type"]="application/json"; body=j; }
    void html(const std::string& h){ headers["Content-Type"]="text/html; charset=utf-8"; body=h; }

    void err(int code, const std::string& msg){
        status=code; statusText=msg;
        headers["Content-Type"]="application/json";
        body="{\"error\":\""+msg+"\"}";
    }
    std::string build() const {
        std::ostringstream o;
        o<<"HTTP/1.1 "<<status<<" "<<statusText<<"\r\n";
        o<<"Access-Control-Allow-Origin: *\r\n";
        o<<"Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS\r\n";
        o<<"Access-Control-Allow-Headers: Content-Type,Authorization\r\n";
        o<<"Connection: close\r\n";
        for(auto&h:headers) o<<h.first<<": "<<h.second<<"\r\n";
        o<<"Content-Length: "<<body.size()<<"\r\n\r\n"<<body;
        return o.str();
    }
};

// Read the full HTTP request from a socket (handles body correctly)
static Req readRequest(int fd){
    Req req;
    std::string raw; raw.reserve(4096);
    char buf[4096];
    // read until headers end
    while(true){
        int n=recv(fd,buf,sizeof(buf)-1,0);
        if(n<=0) break;
        buf[n]=0; raw+=buf;
        if(raw.find("\r\n\r\n")!=std::string::npos) break;
    }
    // parse status line
    std::istringstream ss(raw);
    std::string line, fullPath;
    std::getline(ss,line);
    if(!line.empty()&&line.back()=='\r') line.pop_back();
    std::istringstream rl(line);
    rl>>req.method>>fullPath;
    // strip query string from path (we don't use it server-side)
    auto qp=fullPath.find('?');
    req.path=(qp!=std::string::npos)?fullPath.substr(0,qp):fullPath;
    // parse headers
    while(std::getline(ss,line)){
        if(!line.empty()&&line.back()=='\r') line.pop_back();
        if(line.empty()) break;
        auto col=line.find(':');
        if(col!=std::string::npos){
            auto k=toLower(line.substr(0,col));
            auto v=line.substr(col+2); // skip ": "
            req.headers[k]=v;
        }
    }
    // read body if present
    int bodyLen=0;
    auto it=req.headers.find("content-length");
    if(it!=req.headers.end()) try{ bodyLen=std::stoi(it->second); }catch(...){}
    if(bodyLen>0){
        // how many body bytes already in raw?
        auto bodyStart=raw.find("\r\n\r\n");
        if(bodyStart!=std::string::npos){
            bodyStart+=4;
            req.body=raw.substr(bodyStart);
            while((int)req.body.size()<bodyLen){
                int n=recv(fd,buf,sizeof(buf)-1,0);
                if(n<=0) break;
                buf[n]=0; req.body+=buf;
            }
        }
    }
    return req;
}

// Route matching: /api/events/:id  →  params["id"]
static bool matchRoute(const std::string& pattern, const std::string& path,
                        std::unordered_map<std::string,std::string>& params){
    auto split=[](const std::string& s, char d){
        std::vector<std::string> v; std::istringstream ss(s); std::string t;
        while(std::getline(ss,t,d)) if(!t.empty()) v.push_back(t);
        return v;
    };
    auto pp=split(pattern,'/'), rp=split(path,'/');
    if(pp.size()!=rp.size()) return false;
    params.clear();
    for(size_t i=0;i<pp.size();i++){
        if(pp[i][0]==':') params[pp[i].substr(1)]=rp[i];
        else if(pp[i]!=rp[i]) return false;
    }
    return true;
}

// ─── token helper ────────────────────────────────────────────────
static std::string getToken(const Req& req){
    auto it=req.headers.find("authorization");
    if(it!=req.headers.end()){
        const auto& v=it->second;
        if(v.size()>7 && v.substr(0,7)=="Bearer ") return v.substr(7);
    }
    return "";
}

// ═══════════════════════════════════════════════════════════════════
//  §10  Server
// ═══════════════════════════════════════════════════════════════════
struct Route{
    std::string method, pattern;
    std::function<void(const Req&,Res&)> handler;
};

class Server {
    int                                                               fd_=-1;
    std::atomic<bool>                                                 running_{false};
    std::vector<Route>                                                routes_;
    std::string                                                       html_;
    std::map<std::string,std::function<void(int,const Req&)>>         sse_;

    void dispatch(int cfd){
        Req req=readRequest(cfd);
        if(req.method.empty()){ close(cfd); return; }

        // SSE upgrade?
        if(req.method=="GET"){
            auto sit=sse_.find(req.path);
            if(sit!=sse_.end()){ sit->second(cfd,req); return; } // handler owns cfd
        }

        Res res;
        if(req.method=="OPTIONS"){
            res.status=204; res.statusText="No Content";
        } else if(req.path=="/"||req.path=="/index.html"){
            res.html(html_);
        } else {
            bool found=false;
            for(auto& r:routes_){
                if(r.method!=req.method) continue;
                std::unordered_map<std::string,std::string> params;
                if(matchRoute(r.pattern,req.path,params)){
                    const_cast<Req&>(req).params=params;
                    try{ r.handler(req,res); } catch(std::exception& e){ res.err(500,e.what()); }
                    found=true; break;
                }
            }
            if(!found) res.err(404,"Not found");
        }
        auto out=res.build();
        ::send(cfd,out.c_str(),out.size(),MSG_NOSIGNAL);
        close(cfd);
    }

public:
    void route(const std::string& m, const std::string& p, std::function<void(const Req&,Res&)> h){
        routes_.push_back({m,p,h});
    }
    void sse(const std::string& p, std::function<void(int,const Req&)> h){ sse_[p]=h; }
    void setHtml(const std::string& h){ html_=h; }

    bool listen(int port){
        signal(SIGPIPE,SIG_IGN);
        fd_=socket(AF_INET,SOCK_STREAM,0);
        if(fd_<0){ std::cerr<<"socket() failed\n"; return false; }
        int opt=1; setsockopt(fd_,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
        sockaddr_in addr{}; addr.sin_family=AF_INET;
        addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons((uint16_t)port);
        if(bind(fd_,(sockaddr*)&addr,sizeof(addr))<0){ std::cerr<<"bind() failed\n"; return false; }
        if(::listen(fd_,256)<0){ std::cerr<<"listen() failed\n"; return false; }
        running_=true;
        while(running_){
            sockaddr_in ca{}; socklen_t cl=sizeof(ca);
            int cfd=accept(fd_,(sockaddr*)&ca,&cl);
            if(cfd<0) continue;
            std::thread([this,cfd]{ this->dispatch(cfd); }).detach();
        }
        close(fd_); return true;
    }
};

// ═══════════════════════════════════════════════════════════════════
//  §11  Route handlers
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
//  §11b  Resend email mailer  (HTTPS API, port 443)
// ═══════════════════════════════════════════════════════════════════
struct Mailer {
    std::string apiKey;
    std::string fromAddr;
    bool        enabled=false;

    void init(){
        const char* k=std::getenv("RESEND_API_KEY");
        const char* f=std::getenv("RESEND_FROM"); // optional custom from address
        if(k&&strlen(k)>0){
            apiKey=k;
            fromAddr=f&&strlen(f)>0 ? std::string(f) : "Residence Portal <onboarding@resend.dev>";
            enabled=true;
            std::cout<<"  Email: Resend enabled (from: "<<fromAddr<<")\n";
        } else {
            std::cout<<"  Email: disabled (set RESEND_API_KEY to enable)\n";
        }
    }

    // Send via Resend HTTPS API using OpenSSL BIO
    bool send(const std::string& toAddr, const std::string& toName,
              const std::string& subject, const std::string& bodyText){
        if(!enabled||toAddr.empty()) return false;
        try{
            // Build JSON payload
            std::string payload=
                "{\"from\":\""+fromAddr+"\","
                "\"to\":[\""+toAddr+"\"],"
                "\"subject\":\""+subject+"\","
                "\"text\":\""+[&](){
                    std::string s;
                    for(char c:bodyText){
                        if(c=='"') s+="\\\"";
                        else if(c=='\\') s+="\\\\";
                        else if(c=='\n') s+="\\n";
                        else if(c=='\r') s+="\\r";
                        else s+=c;
                    }
                    return s;
                }()+"\"}";

            // Build HTTP request
            std::string httpReq=
                "POST /emails HTTP/1.1\r\n"
                "Host: api.resend.com\r\n"
                "Authorization: Bearer "+apiKey+"\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: "+std::to_string(payload.size())+"\r\n"
                "Connection: close\r\n"
                "\r\n"+payload;

            // Connect via SSL
            SSL_CTX* ctx=SSL_CTX_new(TLS_client_method());
            if(!ctx){ std::cerr<<"  Resend: SSL_CTX_new failed\n"; return false; }
            SSL_CTX_set_verify(ctx,SSL_VERIFY_NONE,nullptr);

            BIO* bio=BIO_new_ssl_connect(ctx);
            if(!bio){ SSL_CTX_free(ctx); std::cerr<<"  Resend: BIO create failed\n"; return false; }

            BIO_set_conn_hostname(bio,"api.resend.com:443");
            SSL* ssl=nullptr;
            BIO_get_ssl(bio,&ssl);
            if(ssl) SSL_set_tlsext_host_name(ssl,"api.resend.com");

            if(BIO_do_connect(bio)<=0){
                std::cerr<<"  Resend: connect to api.resend.com:443 failed\n";
                BIO_free_all(bio); SSL_CTX_free(ctx); return false;
            }
            if(BIO_do_handshake(bio)<=0){
                std::cerr<<"  Resend: TLS handshake failed\n";
                BIO_free_all(bio); SSL_CTX_free(ctx); return false;
            }

            // Send request
            BIO_write(bio,httpReq.c_str(),(int)httpReq.size());

            // Read response
            std::string resp; char buf[4096]={};
            int n;
            while((n=BIO_read(bio,buf,sizeof(buf)-1))>0){
                buf[n]=0; resp+=buf;
            }
            BIO_free_all(bio); SSL_CTX_free(ctx);

            // Check HTTP status
            bool ok=resp.find("200 OK")!=std::string::npos||resp.find("201")!=std::string::npos;
            if(ok){
                std::cout<<"  Resend: email sent OK to "<<toAddr<<"\n";
            } else {
                // Print first line of response for debugging
                auto nl=resp.find('\n');
                std::cerr<<"  Resend: send failed — "<<resp.substr(0,nl==std::string::npos?200:nl)<<"\n";
                // Print body too
                auto body_start=resp.find("\r\n\r\n");
                if(body_start!=std::string::npos)
                    std::cerr<<"  Resend body: "<<resp.substr(body_start+4,300)<<"\n";
            }
            return ok;
        } catch(const std::exception& e){
            std::cerr<<"  Resend exception: "<<e.what()<<"\n"; return false;
        } catch(...){
            std::cerr<<"  Resend: unknown error\n"; return false;
        }
    }

    // Send async (fire-and-forget)
    void sendAsync(const std::string& toAddr, const std::string& toName,
                   const std::string& subject, const std::string& body){
        if(!enabled||toAddr.empty()) return;
        std::thread([this,toAddr,toName,subject,body]{
            send(toAddr,toName,subject,body);
        }).detach();
    }

    // Broadcast to all residents with email
    void broadcast(const std::vector<User>& users,
                   const std::string& subject, const std::string& body){
        if(!enabled) return;
        for(auto&u:users){
            if(!u.email.empty()&&u.role!="admin")
                sendAsync(u.email,u.name,subject,body);
        }
    }
};
// ═══════════════════════════════════════════════════════════════════
static const char FRONTEND[] = R"HTMLEOF(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Residence Portal</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@500;700&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --cream:#f5f0e8;--cream2:#ede7d9;--cream3:#e4dccb;--parchment:#faf7f2;
  --slate:#2c3341;--slate2:#3d4758;
  --amber:#c9803a;--amber2:#e09550;--amber3:#f5b06a;
  --green:#4a7c59;--green2:#5d9970;
  --red:#b85450;--red2:#d96b67;
  --muted:#7a8494;--border:#ddd5c4;
  --shadow:rgba(44,51,65,.10);--shadow2:rgba(44,51,65,.18);
  --serif:'Playfair Display',Georgia,serif;
  --sans:'DM Sans',system-ui,sans-serif;
  --r:10px;--r2:16px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--cream);color:var(--slate);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh}

/* ── AUTH SCREEN ─────────────────────────────────── */
#auth-screen{
  position:fixed;inset:0;z-index:1000;
  background:linear-gradient(135deg,#1e2530 0%,var(--slate) 60%,var(--slate2) 100%);
  display:flex;align-items:center;justify-content:center;padding:20px;
}
.auth-card{
  background:var(--parchment);border:1px solid var(--border);border-radius:20px;
  padding:40px;width:100%;max-width:460px;
  box-shadow:0 32px 80px rgba(0,0,0,.4);
  animation:cardIn .45s cubic-bezier(.16,1,.3,1);
}
@keyframes cardIn{from{opacity:0;transform:translateY(28px) scale(.97)}to{opacity:1;transform:none}}
.auth-logo{display:flex;align-items:center;gap:14px;margin-bottom:28px}
.auth-logo-icon{width:48px;height:48px;background:var(--amber);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;flex-shrink:0}
.auth-logo-name{font-family:var(--serif);font-size:22px;font-weight:700;color:var(--slate);line-height:1.15}
.auth-logo-sub{font-size:12px;color:var(--muted)}
.auth-tabs{display:flex;background:var(--cream2);border-radius:var(--r);padding:4px;gap:4px;margin-bottom:24px}
.auth-tab{flex:1;padding:8px;border:none;border-radius:8px;background:none;font-family:var(--sans);font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;transition:all .2s}
.auth-tab.active{background:#fff;color:var(--slate);box-shadow:0 1px 6px var(--shadow)}
.auth-panel{display:none}
.auth-panel.active{display:block}
.auth-panel-title{font-family:var(--serif);font-size:22px;font-weight:700;color:var(--slate);margin-bottom:4px}
.auth-panel-sub{font-size:13px;color:var(--muted);margin-bottom:20px}
.auth-err{background:rgba(185,84,80,.09);border:1.5px solid rgba(185,84,80,.3);border-radius:var(--r);padding:10px 14px;font-size:13px;color:var(--red);margin-bottom:14px;display:none}
.auth-err.show{display:block}
.auth-link{font-size:12px;text-align:center;color:var(--muted);margin-top:14px}
.auth-link a{color:var(--amber);font-weight:600;text-decoration:none;cursor:pointer}
.auth-link a:hover{text-decoration:underline}

/* ── FORMS ───────────────────────────────────────── */
.fg{margin-bottom:14px}
.fg label{display:block;font-size:11px;font-weight:600;color:var(--slate2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.fg input,.fg select,.fg textarea{width:100%;background:#fff;border:1.5px solid var(--border);border-radius:var(--r);padding:10px 13px;font-family:var(--sans);font-size:14px;color:var(--slate);outline:none;transition:border .18s,box-shadow .18s}
.fg input:focus,.fg select:focus,.fg textarea:focus{border-color:var(--amber);box-shadow:0 0 0 3px rgba(201,128,58,.12)}
.fg input::placeholder{color:var(--muted)}
.fg textarea{min-height:82px;resize:vertical}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:12px}

/* ── TOPBAR ──────────────────────────────────────── */
#topbar{background:var(--slate);color:#fff;padding:0 24px;display:flex;align-items:center;height:58px;position:sticky;top:0;z-index:100;box-shadow:0 2px 18px var(--shadow2)}
.brand{font-family:var(--serif);font-size:19px;font-weight:700;color:var(--amber3);margin-right:20px;display:flex;align-items:center;gap:10px;cursor:pointer;flex-shrink:0;user-select:none}
.brand-icon{width:32px;height:32px;background:var(--amber);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px}
#nav{display:flex;gap:2px;flex:1;overflow-x:auto;scrollbar-width:none}
#nav::-webkit-scrollbar{display:none}
.nb{background:none;border:none;color:rgba(255,255,255,.6);font-family:var(--sans);font-size:13px;font-weight:500;padding:6px 14px;border-radius:6px;cursor:pointer;white-space:nowrap;transition:all .2s}
.nb:hover{color:#fff;background:rgba(255,255,255,.08)}
.nb.active{color:var(--amber3);background:rgba(201,128,58,.15)}
#user-area{margin-left:auto;display:flex;align-items:center;gap:10px;flex-shrink:0}
.uc{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.15);border-radius:20px;padding:4px 14px 4px 6px}
.ua{width:26px;height:26px;background:var(--amber);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0}
.un{color:#fff;font-size:12px;font-weight:600;line-height:1.2}
.ur{color:rgba(255,255,255,.5);font-size:10px;line-height:1.2}
.logout-btn{background:none;border:1px solid rgba(255,255,255,.2);border-radius:6px;color:rgba(255,255,255,.55);font-family:var(--sans);font-size:11px;font-weight:600;padding:5px 10px;cursor:pointer;transition:all .2s}
.logout-btn:hover{background:rgba(255,255,255,.1);color:#fff}

/* ── NOTICES ─────────────────────────────────────── */
#notice-bar{background:linear-gradient(135deg,var(--amber) 0%,var(--amber2) 100%);color:#fff;display:none}
#notice-bar.show{display:block}
.ni{max-width:1100px;margin:0 auto;padding:10px 24px;display:flex;gap:10px;align-items:flex-start}
.ni-icon{font-size:15px;margin-top:2px;flex-shrink:0}
.ni-item{font-size:13px;font-weight:500;line-height:1.5}
.ni-item+.ni-item{margin-top:4px;padding-top:4px;border-top:1px solid rgba(255,255,255,.25)}
.ni-urg{font-weight:700}

/* ── MAIN / PAGES ────────────────────────────────── */
main{max-width:1100px;margin:0 auto;padding:32px 24px 64px;width:100%}
.page{display:none;animation:fadeIn .3s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.pt{font-family:var(--serif);font-size:32px;font-weight:700;margin-bottom:6px;letter-spacing:-.5px}
.ps{color:var(--muted);font-size:14px;margin-bottom:28px}
.st{font-family:var(--serif);font-size:20px;font-weight:500;color:var(--slate);margin-bottom:16px;display:flex;align-items:center;gap:10px}
.st::after{content:'';flex:1;height:1px;background:var(--border)}

/* ── CARDS ───────────────────────────────────────── */
.card{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:20px 22px;box-shadow:0 2px 8px var(--shadow);transition:box-shadow .2s,transform .2s}
.card:hover{box-shadow:0 6px 20px var(--shadow2);transform:translateY(-2px)}
.grid{display:grid;gap:16px}
.grid2{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}

/* ── BADGES ──────────────────────────────────────── */
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.3px;text-transform:uppercase}
.bk{background:rgba(74,124,89,.15);color:var(--green)}
.bl{background:rgba(100,140,200,.15);color:#4a6fa5}
.bm{background:rgba(185,84,80,.12);color:var(--red)}
.bg{background:rgba(201,128,58,.15);color:var(--amber)}
.bu{background:rgba(74,124,89,.15);color:var(--green)}
.bp{background:rgba(120,130,148,.15);color:var(--muted)}
.bf{background:rgba(185,84,80,.12);color:var(--red)}

/* ── BUTTONS ─────────────────────────────────────── */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border:none;border-radius:var(--r);font-family:var(--sans);font-size:13px;font-weight:600;cursor:pointer;transition:all .18s;white-space:nowrap;text-decoration:none}
.btn-p{background:var(--amber);color:#fff}.btn-p:hover{background:var(--amber2);transform:translateY(-1px);box-shadow:0 4px 14px rgba(201,128,58,.35)}
.btn-s{background:var(--slate);color:#fff}.btn-s:hover{background:var(--slate2);transform:translateY(-1px)}
.btn-g{background:var(--green);color:#fff}.btn-g:hover{background:var(--green2)}
.btn-r{background:var(--red);color:#fff}.btn-r:hover{background:var(--red2)}
.btn-gh{background:transparent;color:var(--slate);border:1.5px solid var(--border)}.btn-gh:hover{border-color:var(--amber);color:var(--amber)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-full{width:100%;justify-content:center}

/* ── TOOLBAR ─────────────────────────────────────── */
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:22px;flex-wrap:wrap}
.toolbar input,.toolbar select{background:#fff;border:1.5px solid var(--border);border-radius:var(--r);padding:8px 13px;font-family:var(--sans);font-size:13px;color:var(--slate);outline:none;transition:border .18s}
.toolbar input:focus,.toolbar select:focus{border-color:var(--amber)}
.toolbar input{flex:1;min-width:180px}
.toolbar input::placeholder{color:var(--muted)}

/* ── DASHBOARD ───────────────────────────────────── */
.hero{background:linear-gradient(135deg,var(--slate) 0%,var(--slate2) 100%);color:#fff;border-radius:var(--r2);padding:36px;margin-bottom:28px;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:-40px;right:-40px;width:220px;height:220px;background:radial-gradient(circle,rgba(201,128,58,.25) 0%,transparent 70%);border-radius:50%}
.hero-title{font-family:var(--serif);font-size:32px;font-weight:700;margin-bottom:6px;position:relative}
.hero-sub{color:rgba(255,255,255,.65);font-size:15px;position:relative}
.hero-date{position:absolute;top:22px;right:28px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);padding:10px 18px;border-radius:var(--r);text-align:right}
.clock-time{font-size:26px;font-weight:700;font-family:var(--sans);color:#fff;letter-spacing:2px;line-height:1}
.clock-date{font-size:12px;color:rgba(255,255,255,.7);margin-top:4px;letter-spacing:.3px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:28px}
.sc{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:18px 20px;box-shadow:0 2px 8px var(--shadow)}
.sc-lbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}
.sc-val{font-family:var(--serif);font-size:28px;font-weight:700;color:var(--slate);margin-top:2px}
.dash-grid{display:grid;grid-template-columns:1fr 370px;gap:24px}
@media(max-width:820px){.dash-grid{grid-template-columns:1fr}}
.mini-cal{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:18px 20px;box-shadow:0 2px 8px var(--shadow);margin-bottom:24px}
.mini-cal-head{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.mini-cal-title{font-family:var(--serif);font-size:16px;font-weight:700;color:var(--slate)}
.mini-cal-nav{background:none;border:1px solid var(--border);border-radius:6px;width:28px;height:28px;cursor:pointer;font-size:14px;color:var(--muted);display:flex;align-items:center;justify-content:center;transition:all .15s}
.mini-cal-nav:hover{background:var(--cream2);color:var(--slate)}
.mini-cal-grid{display:grid;grid-template-columns:repeat(7,1fr);gap:3px;text-align:center}
.mini-cal-dow{font-size:10px;font-weight:700;color:var(--muted);padding:3px 0;letter-spacing:.5px;text-transform:uppercase}
.cal-day{font-size:12px;padding:5px 2px;border-radius:6px;cursor:default;color:var(--slate);line-height:1.4;position:relative}
.cal-day.other{color:var(--border)}
.cal-day.today{background:var(--amber);color:#fff;font-weight:700}
.cal-day.has-event{font-weight:700;color:var(--amber)}
.cal-day.has-event::after{content:'';position:absolute;bottom:2px;left:50%;transform:translateX(-50%);width:4px;height:4px;background:var(--amber);border-radius:50%}
.cal-day.today.has-event{background:var(--amber)}
.cal-day.today.has-event::after{background:#fff}
.cal-event-list{margin-top:12px;border-top:1px solid var(--border);padding-top:10px}
.cal-event-item{font-size:12px;padding:5px 8px;border-radius:6px;background:var(--cream2);margin-bottom:5px;display:flex;gap:8px;align-items:center;cursor:pointer}
.cal-event-item:hover{background:var(--cream3)}
.cal-event-dot{width:7px;height:7px;background:var(--amber);border-radius:50%;flex-shrink:0}

/* ── NEWS ────────────────────────────────────────── */
.nc{border-left:3px solid var(--amber)}
.nc-meta{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.nc-title{font-family:var(--serif);font-size:17px;font-weight:500;color:var(--slate);margin-bottom:6px;line-height:1.35}
.nc-body{font-size:14px;color:var(--slate2);line-height:1.65}
.nc-date{font-size:12px;color:var(--muted)}

/* ── EVENTS ──────────────────────────────────────── */
.ec{border-top:3px solid var(--amber)}
.ec.past{border-top-color:var(--border);opacity:.75}
.ec-name{font-family:var(--serif);font-size:18px;font-weight:500;color:var(--slate);margin-bottom:6px}
.ec-meta{display:flex;flex-wrap:wrap;gap:10px;font-size:13px;color:var(--muted)}
.ec-desc{font-size:14px;color:var(--slate2);margin:10px 0 14px;line-height:1.6}
.ec-foot{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.cap-bar{width:110px;height:5px;background:var(--cream3);border-radius:3px;display:inline-block;margin-left:8px;vertical-align:middle;overflow:hidden}
.cap-fill{height:100%;border-radius:3px;background:var(--green);transition:width .4s}
.cap-fill.full{background:var(--red)}
.reg-box{margin-top:14px;border-top:1px solid var(--border);padding-top:14px;display:none}
.reg-box.open{display:block}

/* ── TABLES ──────────────────────────────────────── */
.tw{overflow-x:auto;margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:14px}
thead th{background:var(--slate);color:rgba(255,255,255,.8);padding:10px 14px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;white-space:nowrap}
thead th:first-child{border-radius:8px 0 0 0}
thead th:last-child{border-radius:0 8px 0 0}
tbody tr{border-bottom:1px solid var(--border);transition:background .12s}
tbody tr:hover{background:var(--cream2)}
tbody td{padding:10px 14px;color:var(--slate2)}
tbody td:first-child{color:var(--slate);font-weight:500}
.tbl-empty{text-align:center;color:var(--muted);padding:32px !important;font-style:italic}

/* ── SLOTS ───────────────────────────────────────── */
.slot-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:8px;margin-top:10px}
.slot{padding:9px 12px;border-radius:var(--r);font-size:13px;font-weight:500;text-align:center;cursor:pointer;transition:all .15s;border:1.5px solid var(--border);background:#fff;color:var(--slate)}
.slot:hover{border-color:var(--amber);color:var(--amber)}
.slot.taken{background:var(--cream3);color:var(--muted);cursor:not-allowed;border-style:dashed}
.slot.sel{background:var(--amber);color:#fff;border-color:var(--amber)}
.m-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.mt{padding:6px 16px;border:1.5px solid var(--border);border-radius:20px;background:#fff;font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;color:var(--slate)}
.mt.active{background:var(--slate);color:#fff;border-color:var(--slate)}

/* ── ADMIN ───────────────────────────────────────── */
.adm{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:24px;margin-bottom:20px;box-shadow:0 2px 8px var(--shadow)}
.adm h3{font-family:var(--serif);font-size:18px;color:var(--slate);margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.ar{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--cream3);gap:12px;flex-wrap:wrap}
.ar:last-child{border-bottom:none}
.ar strong{font-size:14px;font-weight:600;color:var(--slate);display:block}
.ar small{font-size:12px;color:var(--muted)}

/* ── TOAST ───────────────────────────────────────── */
#toasts{position:fixed;bottom:22px;right:22px;z-index:999;display:flex;flex-direction:column;gap:8px}
.toast{background:var(--slate);color:#fff;border-radius:var(--r);padding:12px 18px;font-size:13px;box-shadow:0 8px 24px rgba(44,51,65,.3);animation:tIn .28s ease;max-width:300px;display:flex;align-items:center;gap:10px;border-left:3px solid var(--amber)}
.toast.ok{border-left-color:var(--green)}.toast.er{border-left-color:var(--red)}
@keyframes tIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}
.pill{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:500}
.pa{background:rgba(201,128,58,.15);color:var(--amber)}.ps2{background:rgba(44,51,65,.1);color:var(--slate)}
.divider{height:1px;background:var(--border);margin:22px 0}
.empty{text-align:center;padding:44px 24px;color:var(--muted);font-size:14px}
.empty-icon{font-size:38px;display:block;margin-bottom:10px;opacity:.4}
.identity-box{background:var(--cream2);border:1.5px solid var(--border);border-radius:var(--r);padding:10px 13px;font-size:14px;color:var(--slate2);margin-bottom:14px}
</style>
</head>
<body>

<!-- ═══ AUTH SCREEN ═══════════════════════════════════════════════ -->
<div id="auth-screen">
  <div class="auth-card">
    <div class="auth-logo">
      <img src="https://i.imgur.com/esh-Lq2dqye.png" alt="Logo" style="width:52px;height:52px;object-fit:contain;border-radius:10px;flex-shrink:0" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
      <div class="auth-logo-icon" style="display:none">🏠</div>
      <div>
        <div class="auth-logo-name">Residence Portal</div>
        <div class="auth-logo-sub">Shared Living Management System</div>
      </div>
    </div>

    <div class="auth-tabs">
      <button class="auth-tab active" onclick="authTab('login')">Sign In</button>
      <button class="auth-tab"        onclick="authTab('register')">Register</button>
    </div>

    <!-- LOGIN -->
    <div class="auth-panel active" id="ap-login">
      <div class="auth-panel-title">Welcome back</div>
      <div class="auth-panel-sub">Sign in to access news, events and bookings.</div>
      <div class="auth-err" id="login-err"></div>
      <div class="fg"><label>Username</label>
        <input id="l-u" placeholder="Your username" autocomplete="username"
               onkeydown="if(event.key==='Enter')doLogin()"></div>
      <div class="fg"><label>Password</label>
        <input id="l-p" type="password" placeholder="Your password" autocomplete="current-password"
               onkeydown="if(event.key==='Enter')doLogin()"></div>
      <button class="btn btn-p btn-full" style="margin-top:6px" onclick="doLogin()">Sign In →</button>
      <div class="auth-link">No account? <a onclick="authTab('register')">Register here</a></div>
    </div>

    <!-- REGISTER -->
    <div class="auth-panel" id="ap-register">
      <div class="auth-panel-title">Create your account</div>
      <div class="auth-panel-sub">Fill in your details to access the portal.</div>
      <div class="auth-err" id="reg-err"></div>
      <div class="fr">
        <div class="fg"><label>Full Name</label>
          <input id="r-n" placeholder="e.g. Sarah Ahmed"></div>
        <div class="fg"><label>Room Number</label>
          <input id="r-r" placeholder="e.g. 204"></div>
      </div>
      <div class="fr">
        <div class="fg"><label>Email</label>
          <input id="r-e" type="email" placeholder="your@email.com" autocomplete="email"></div>
        <div class="fg"><label>Phone Number</label>
          <input id="r-ph" type="tel" placeholder="e.g. +49 123 456789"></div>
      </div>
      <div class="fg"><label>Username</label>
        <input id="r-u" placeholder="Choose a username" autocomplete="username"></div>
      <div class="fr">
        <div class="fg"><label>Password</label>
          <input id="r-p" type="password" placeholder="Min. 6 characters" autocomplete="new-password"></div>
        <div class="fg"><label>Confirm Password</label>
          <input id="r-p2" type="password" placeholder="Repeat password"
                 onkeydown="if(event.key==='Enter')doRegister()"></div>
      </div>
      <button class="btn btn-p btn-full" style="margin-top:6px" onclick="doRegister()">Create Account →</button>
      <div class="auth-link">Already registered? <a onclick="authTab('login')">Sign in</a></div>
    </div>
  </div>
</div>

<!-- ═══ APP ═══════════════════════════════════════════════════════ -->
<div id="app" style="display:none;flex-direction:column;min-height:100vh">

  <header id="topbar">
    <div class="brand" onclick="showPage('dashboard')">
      <img src="https://i.imgur.com/esh-Lq2dqye.png" alt="Logo" style="width:32px;height:32px;object-fit:contain;border-radius:6px;flex-shrink:0" onerror="this.style.display='none';this.nextElementSibling.style.display='flex'">
      <div class="brand-icon" style="display:none">🏠</div>
      Residence Portal
    </div>
    <nav id="nav">
      <button class="nb active" onclick="showPage('dashboard')" data-page="dashboard">Dashboard</button>
      <button class="nb"        onclick="showPage('news')"      data-page="news">News</button>
      <button class="nb"        onclick="showPage('events')"    data-page="events">Events</button>
      <button class="nb"        onclick="showPage('laundry')"   data-page="laundry">Laundry</button>
      <button class="nb"        onclick="showPage('equip')"     data-page="equip">Equipment</button>
      <button class="nb" id="admin-btn" onclick="showPage('admin')" data-page="admin" style="display:none">⚙ Admin</button>
    </nav>
    <div id="user-area">
      <div class="uc">
        <div class="ua" id="ua">?</div>
        <div><div class="un" id="un">—</div><div class="ur" id="ur">—</div></div>
      </div>
      <button class="logout-btn" onclick="doLogout()">Sign Out</button>
    </div>
  </header>

  <div id="notice-bar">
    <div class="ni">
      <span class="ni-icon">📢</span>
      <div id="ni-items"></div>
    </div>
  </div>

  <main>

    <!-- DASHBOARD -->
    <div class="page active" id="page-dashboard">
      <div class="hero">
        <div class="hero-title" id="hero-title">Good to see you 👋</div>
        <div class="hero-sub">Your Residence Portal — news, events, and bookings in one place.</div>
        <div class="hero-date" id="hero-date">
          <div class="clock-time" id="clock-time">00:00:00</div>
          <div class="clock-date" id="clock-date"></div>
        </div>
      </div>
      <div class="stats">
        <div class="sc"><div class="sc-lbl">Announcements</div><div class="sc-val" id="st-news">—</div></div>
        <div class="sc"><div class="sc-lbl">Upcoming Events</div><div class="sc-val" id="st-evts">—</div></div>
        <div class="sc"><div class="sc-lbl">Laundry Bookings</div><div class="sc-val" id="st-lnd">—</div></div>
        <div class="sc"><div class="sc-lbl">Equipment</div><div class="sc-val" id="st-eq">—</div></div>
      </div>
      <div class="dash-grid">
        <div>
          <div class="st">Latest Announcements</div>
          <div id="dash-news"></div>
          <button class="btn btn-gh" style="margin-top:14px" onclick="showPage('news')">All news →</button>
        </div>
        <div>
          <div class="st">Upcoming Events</div>
          <div id="dash-evts"></div>
          <button class="btn btn-gh" style="margin-top:14px" onclick="showPage('events')">All events →</button>
        </div>
      </div>
      <!-- MINI CALENDAR -->
      <div class="mini-cal" id="mini-cal-widget">
        <div class="mini-cal-head">
          <div class="mini-cal-title" id="cal-month-label"></div>
          <div style="display:flex;gap:6px">
            <button class="mini-cal-nav" onclick="calNav(-1)">‹</button>
            <button class="mini-cal-nav" onclick="calNav(1)">›</button>
          </div>
        </div>
        <div class="mini-cal-grid" id="cal-grid"></div>
        <div class="cal-event-list" id="cal-event-list"></div>
      </div>
    </div>

    <!-- NEWS -->
    <div class="page" id="page-news">
      <div class="pt">News & Announcements</div>
      <div class="ps">Building updates, policy changes, and management notices.</div>
      <div class="toolbar">
        <input id="news-q" placeholder="🔍 Search announcements…" oninput="renderNews()">
        <select id="news-cat" onchange="renderNews()">
          <option value="">All Categories</option>
          <option>Kitchen</option><option>Laundry</option><option>Maintenance</option><option>General</option>
        </select>
      </div>
      <div class="grid" id="news-list"></div>
    </div>

    <!-- EVENTS -->
    <div class="page" id="page-events">
      <div class="pt">Events</div>
      <div class="ps">Community gatherings and shared activities.</div>
      <div style="display:flex;gap:10px;margin-bottom:22px;flex-wrap:wrap">
        <button class="btn btn-s"  id="ef-all"      onclick="evtFilter('all')">All</button>
        <button class="btn btn-gh" id="ef-upcoming"  onclick="evtFilter('upcoming')">Upcoming</button>
        <button class="btn btn-gh" id="ef-past"      onclick="evtFilter('past')">Past</button>
      </div>
      <div class="grid grid2" id="evts-list"></div>
    </div>

    <!-- LAUNDRY -->
    <div class="page" id="page-laundry">
      <div class="pt">Laundry Booking</div>
      <div class="ps">Reserve a washing machine. The 10-minute rule applies after your cycle ends.</div>
      <div style="display:grid;grid-template-columns:1fr 360px;gap:24px;align-items:start">
        <div>
          <div class="st">Make a Reservation</div>
          <div class="adm" style="padding:22px">
            <div class="fg"><label>Booking for</label>
              <div class="identity-box" id="lb-id">—</div>
            </div>
            <div class="fg"><label>Machine</label>
              <div class="m-tabs">
                <button class="mt active" data-m="M1" onclick="selMachine(this)">Machine 1</button>
                <button class="mt" data-m="M2" onclick="selMachine(this)">Machine 2</button>
                <button class="mt" data-m="M3" onclick="selMachine(this)">Machine 3</button>
              </div>
            </div>
            <div class="fg"><label>Date</label><input type="date" id="lb-date" onchange="renderSlots()"></div>
            <div class="fg">
              <label>Time Slot</label>
              <div class="slot-grid" id="lb-slots"><div style="color:var(--muted);font-size:13px">Choose a date above.</div></div>
            </div>
            <input type="hidden" id="lb-slot">
            <button class="btn btn-p btn-full" onclick="bookLaundry()">Confirm Reservation</button>
          </div>
        </div>
        <div>
          <div class="st">All Reservations</div>
          <div class="tw">
            <table><thead><tr><th>Name</th><th>Room</th><th>Machine</th><th>Date</th><th>Slot</th><th></th></tr></thead>
            <tbody id="lnd-tbody"></tbody></table>
          </div>
        </div>
      </div>
    </div>

    <!-- EQUIPMENT -->
    <div class="page" id="page-equip">
      <div class="pt">Equipment Booking</div>
      <div class="ps">Reserve shared equipment. Maximum 1 hour per item per day per resident.</div>

      <!-- LIVE STATUS BOARD -->
      <div class="st">📊 Equipment Status Board</div>
      <div id="equip-board" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:14px;margin-bottom:32px"></div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;align-items:start">
        <!-- BOOKING FORM -->
        <div>
          <div class="st">Book Equipment</div>
          <div class="adm" style="padding:22px">
            <div class="fg"><label>Booking for</label>
              <div class="identity-box" id="eq-id">—</div>
            </div>
            <div class="fg"><label>Equipment</label>
              <select id="eq-item">
                <option value="Vacuum Cleaner">🧹 Vacuum Cleaner (max 1hr/day)</option>
                <option value="Ladder">🪜 Ladder</option>
                <option value="Power Drill">🔧 Power Drill</option>
                <option value="Ironing Board">👔 Ironing Board</option>
              </select>
            </div>
            <div class="fg"><label>Date</label><input type="date" id="eq-date"></div>
            <div class="fr">
              <div class="fg"><label>Start Time</label><input type="time" id="eq-start" placeholder="e.g. 14:00"></div>
              <div class="fg"><label>End Time</label><input type="time" id="eq-end" placeholder="e.g. 15:00"></div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
              <span class="pill pa">📋 Max 1 hour per item per day</span>
              <span class="pill ps2">Return equipment after use</span>
            </div>
            <button class="btn btn-p btn-full" onclick="bookEquip()">Book Equipment</button>
          </div>
        </div>

      <!-- FULL BOOKINGS TABLE -->
      <div class="st" style="margin-top:28px">All Equipment Bookings</div>
      <div class="tw">
        <table><thead><tr><th>Name</th><th>Room</th><th>Item</th><th>Date</th><th>From</th><th>Until</th><th></th></tr></thead>
        <tbody id="eq-tbody"></tbody></table>
      </div>
      </div><!-- end grid -->
    </div><!-- end page-equip -->

    <!-- ADMIN -->
    <div class="page" id="page-admin">
      <div class="pt">Administration</div>
      <div class="ps">Manage notices, news, events, bookings, and residents.</div>

      <div class="adm">
        <h3>📢 Notices</h3>
        <div class="fr" style="margin-bottom:12px">
          <div class="fg"><label>Notice Text</label><input id="adm-nt" placeholder="Enter notice…"></div>
          <div class="fg" style="display:flex;align-items:flex-end;padding-bottom:0">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;text-transform:none;letter-spacing:0;margin-bottom:0">
              <input type="checkbox" id="adm-nu" style="width:auto"> Urgent
            </label>
          </div>
        </div>
        <button class="btn btn-p btn-sm" onclick="addNotice()">Post Notice</button>
        <div class="divider"></div>
        <div id="adm-notices"></div>
      </div>

      <div class="adm">
        <h3>📰 Post News</h3>
        <div class="fr">
          <div class="fg"><label>Title</label><input id="adm-nwt" placeholder="Announcement title"></div>
          <div class="fg"><label>Category</label>
            <select id="adm-nwc"><option>Kitchen</option><option>Laundry</option><option>Maintenance</option><option>General</option></select>
          </div>
        </div>
        <div class="fg"><label>Date</label><input type="date" id="adm-nwd" style="max-width:200px"></div>
        <div class="fg"><label>Content</label><textarea id="adm-nwb" placeholder="Full announcement text…"></textarea></div>
        <button class="btn btn-p" onclick="postNews()">Publish</button>
      </div>

      <div class="adm">
        <h3>🎉 Create Event</h3>
        <div class="fr">
          <div class="fg"><label>Event Name</label><input id="adm-en" placeholder="e.g. Game Night"></div>
          <div class="fg"><label>Location</label><input id="adm-el" placeholder="e.g. Lounge Area"></div>
        </div>
        <div class="fr">
          <div class="fg"><label>Date</label><input type="date" id="adm-ed"></div>
          <div class="fg"><label>Time</label><input type="time" id="adm-et"></div>
        </div>
        <div class="fg"><label>Max Participants</label><input type="number" id="adm-em" placeholder="20" min="1" style="max-width:120px"></div>
        <div class="fg"><label>Description</label><textarea id="adm-edesc" placeholder="What's happening?"></textarea></div>
        <button class="btn btn-p" onclick="createEvent()">Create Event</button>
      </div>

      <div class="adm"><h3>📋 Manage News</h3><div id="adm-news"></div></div>
      <div class="adm"><h3>📋 Manage Events</h3><div id="adm-evts"></div></div>

      <div class="adm">
        <h3>👥 Registered Residents</h3>
        <div class="tw"><table>
          <thead><tr><th>Name</th><th>Room</th><th>Username</th><th>Email</th><th>Phone</th><th>Role</th><th>Joined</th><th></th></tr></thead>
          <tbody id="adm-users"></tbody>
        </table></div>
      </div>

      <div class="adm">
        <h3>🧺 All Laundry Bookings</h3>
        <div class="tw"><table>
          <thead><tr><th>Name</th><th>Room</th><th>Machine</th><th>Date</th><th>Slot</th><th></th></tr></thead>
          <tbody id="adm-lnd"></tbody>
        </table></div>
      </div>

      <div class="adm">
        <h3>🔧 All Equipment Bookings</h3>
        <div class="tw"><table>
          <thead><tr><th>Name</th><th>Room</th><th>Item</th><th>Date</th><th>From</th><th>Until</th><th></th></tr></thead>
          <tbody id="adm-eq"></tbody>
        </table></div>
      </div>
    </div>

  </main>
</div><!-- #app -->

<div id="toasts"></div>

<script>
// ── STATE ───────────────────────────────────────────────────────
let token='', me=null;
let NEWS=[], EVTS=[], LND=[], EQ=[], NOTICES=[];
let evtF='all', selM='M1', selSlot='';

// ── AUTH STORAGE ────────────────────────────────────────────────
function saveAuth(t,u){ token=t; me=u; try{localStorage.setItem('res_t',t);localStorage.setItem('res_u',JSON.stringify(u));}catch(e){} }
function loadAuth(){ try{token=localStorage.getItem('res_t')||'';const u=localStorage.getItem('res_u');if(u)me=JSON.parse(u);}catch(e){} }
function clearAuth(){ token=''; me=null; try{localStorage.removeItem('res_t');localStorage.removeItem('res_u');}catch(e){} }

// ── API ─────────────────────────────────────────────────────────
async function api(method, path, body){
  try{
    const opts={method, headers:{'Content-Type':'application/json'}};
    if(token) opts.headers['Authorization']='Bearer '+token;
    if(body) opts.body=JSON.stringify(body);
    const r=await fetch(path,opts);
    return await r.json();
  }catch(e){ toast('Connection error','er'); return null; }
}
const GET  = p    => api('GET',p);
const POST = (p,b)=> api('POST',p,b);
const DEL  = p    => api('DELETE',p);

// ── SSE ─────────────────────────────────────────────────────────
let sse=null;
function connectSSE(){
  if(sse) sse.close();
  // Pass token via path since EventSource doesn't support headers
  sse=new EventSource('/api/stream?t='+token);
  sse.addEventListener('notices',  e=>{NOTICES=JSON.parse(e.data);renderNotices();renderAdmNotices();});
  sse.addEventListener('news',     ()=>loadNews());
  sse.addEventListener('news-deleted',()=>loadNews());
  sse.addEventListener('events',   e=>{EVTS=JSON.parse(e.data);renderEvts();renderDashEvts();renderAdmEvts();updateStats();});
  sse.addEventListener('laundry',  e=>{LND=JSON.parse(e.data);renderLnd();renderAdmLnd();renderSlots();updateStats();});
  sse.addEventListener('equip',    e=>{EQ=JSON.parse(e.data);renderEq();renderAdmEq();updateStats();});
  sse.onerror=()=>{};
}

// ── AUTH UI ─────────────────────────────────────────────────────
function authTab(t){
  document.querySelectorAll('.auth-tab').forEach((b,i)=>b.classList.toggle('active',(t==='login'&&i===0)||(t==='register'&&i===1)));
  document.getElementById('ap-login').classList.toggle('active',t==='login');
  document.getElementById('ap-register').classList.toggle('active',t==='register');
  ['login-err','reg-err'].forEach(id=>{const el=document.getElementById(id);el.classList.remove('show');el.textContent='';});
}
function authErr(id,msg){ const el=document.getElementById(id); el.textContent=msg; el.classList.add('show'); }

async function doLogin(){
  const u=document.getElementById('l-u').value.trim();
  const p=document.getElementById('l-p').value;
  if(!u||!p){ authErr('login-err','Please enter your username and password.'); return; }
  const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
  const d=await r.json();
  if(d.error){ authErr('login-err',d.error); return; }
  saveAuth(d.token,d.user); bootApp();
}

async function doRegister(){
  const name=document.getElementById('r-n').value.trim();
  const room=document.getElementById('r-r').value.trim();
  const email=document.getElementById('r-e').value.trim();
  const phone=document.getElementById('r-ph').value.trim();
  const uname=document.getElementById('r-u').value.trim();
  const pw=document.getElementById('r-p').value;
  const pw2=document.getElementById('r-p2').value;
  if(!name||!room||!uname||!pw){ authErr('reg-err','Name, room, username and password are required.'); return; }
  if(pw!==pw2){ authErr('reg-err','Passwords do not match.'); return; }
  if(pw.length<6){ authErr('reg-err','Password must be at least 6 characters.'); return; }
  const r=await fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,room,email,phone,username:uname,password:pw})});
  const d=await r.json();
  if(d.error){ authErr('reg-err',d.error); return; }
  saveAuth(d.token,d.user); bootApp();
}

async function doLogout(){
  await POST('/api/auth/logout');
  clearAuth(); if(sse) sse.close();
  document.getElementById('auth-screen').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('l-u').value=''; document.getElementById('l-p').value='';
}

// ── BOOT ────────────────────────────────────────────────────────
function bootApp(){
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  // topbar
  document.getElementById('un').textContent=me.name;
  document.getElementById('ur').textContent='Room '+me.room;
  document.getElementById('ua').textContent=(me.name[0]||'?').toUpperCase();
  // hero
  document.getElementById('hero-title').textContent='Welcome back, '+me.name.split(' ')[0]+' 👋';
  // admin nav
  document.getElementById('admin-btn').style.display=me.role==='admin'?'':'none';
  // identity labels in booking pages
  const idLabel=me.name+' — Room '+me.room;
  document.getElementById('lb-id').textContent=idLabel;
  document.getElementById('eq-id').textContent=idLabel;
  // default dates
  const td=today();
  document.getElementById('lb-date').value=td;
  document.getElementById('eq-date').value=td;
  document.getElementById('adm-nwd').value=td;
  // connect SSE + load data
  connectSSE();
  Promise.all([loadNews(),loadEvts(),loadLnd(),loadEq(),loadNotices()]);
  if(me.role==='admin') loadAdmUsers();
  startClock();
  renderMiniCal();
}

async function checkExistingSession(){
  loadAuth();
  if(!token) return;
  const r=await fetch('/api/auth/me',{headers:{'Authorization':'Bearer '+token}});
  if(r.ok){ me=await r.json(); bootApp(); }
  else clearAuth();
}

// ── LOADERS ─────────────────────────────────────────────────────
async function loadNews(){ const d=await GET('/api/news'); if(Array.isArray(d)){NEWS=d;renderNews();renderDashNews();updateStats();}}
async function loadEvts(){ const d=await GET('/api/events'); if(Array.isArray(d)){EVTS=d;window._allEvents=d;renderEvts();renderDashEvts();renderAdmEvts();updateStats();renderMiniCal();}}
async function loadLnd(){ const d=await GET('/api/laundry'); if(Array.isArray(d)){LND=d;renderLnd();renderAdmLnd();renderSlots();updateStats();}}
async function loadEq(){ const d=await GET('/api/equip'); if(Array.isArray(d)){EQ=d;renderEq();renderAdmEq();updateStats();}}
async function loadNotices(){ const d=await GET('/api/notices'); if(Array.isArray(d)){NOTICES=d;renderNotices();renderAdmNotices();}}
async function loadAdmUsers(){ const d=await GET('/api/users'); if(Array.isArray(d)) renderAdmUsers(d); }

// ── STATS ────────────────────────────────────────────────────────
const today=()=>new Date().toISOString().split('T')[0];
const fmt=d=>new Date(d+'T00:00:00').toLocaleDateString('en-GB',{weekday:'short',day:'numeric',month:'short',year:'numeric'});
const fmts=d=>new Date(d+'T00:00:00').toLocaleDateString('en-GB',{day:'numeric',month:'short'});

function updateStats(){
  document.getElementById('st-news').textContent=NEWS.length;
  document.getElementById('st-evts').textContent=EVTS.filter(e=>e.date>=today()).length;
  document.getElementById('st-lnd').textContent=LND.length;
  document.getElementById('st-eq').textContent=EQ.length;
}

// ── NOTICES ──────────────────────────────────────────────────────
function renderNotices(){
  const bar=document.getElementById('notice-bar'), items=document.getElementById('ni-items');
  if(!NOTICES.length){bar.classList.remove('show');return;}
  bar.classList.add('show');
  items.innerHTML=NOTICES.map(n=>`<div class="ni-item${n.urgent?' ni-urg':''}">${n.urgent?'⚠ ':''}${esc(n.text)}</div>`).join('');
}
function renderAdmNotices(){
  const el=document.getElementById('adm-notices');
  if(!NOTICES.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No active notices.</div>';return;}
  el.innerHTML=NOTICES.map(n=>`<div class="ar"><div><strong>${n.urgent?'⚠ ':''}${esc(n.text)}</strong><small>${n.urgent?'Urgent':'General'}</small></div><button class="btn btn-r btn-sm" onclick="delNotice('${n.id}')">Remove</button></div>`).join('');
}
async function addNotice(){
  const txt=document.getElementById('adm-nt').value.trim();
  const urg=document.getElementById('adm-nu').checked;
  if(!txt){toast('Enter notice text','er');return;}
  const r=await POST('/api/notices',{text:txt,urgent:urg});
  if(r&&r.id){document.getElementById('adm-nt').value='';document.getElementById('adm-nu').checked=false;toast('Notice posted','ok');loadNotices();}
  else if(r&&r.error) toast(r.error,'er');
}
async function delNotice(id){ await DEL('/api/notices/'+id); toast('Removed'); loadNotices(); }

// ── NEWS ─────────────────────────────────────────────────────────
const catBadge=c=>{const m={Kitchen:'bk',Laundry:'bl',Maintenance:'bm',General:'bg'};return`<span class="badge ${m[c]||'bg'}">${c}</span>`;};

function renderNews(){
  const q=(document.getElementById('news-q')||{value:''}).value.toLowerCase();
  const cat=(document.getElementById('news-cat')||{value:''}).value;
  const list=NEWS.filter(n=>(!q||n.title.toLowerCase().includes(q)||n.content.toLowerCase().includes(q))&&(!cat||n.category===cat));
  const el=document.getElementById('news-list');
  el.innerHTML=list.length?list.map(n=>`<div class="card nc"><div class="nc-meta">${catBadge(n.category)}<span class="nc-date">${fmt(n.date)}</span></div><div class="nc-title">${esc(n.title)}</div><div class="nc-body">${esc(n.content)}</div></div>`).join('')
    :'<div class="empty"><span class="empty-icon">📄</span>No announcements found.</div>';
}
function renderDashNews(){
  const el=document.getElementById('dash-news');
  el.innerHTML=NEWS.slice(0,3).map(n=>`<div class="card nc" style="margin-bottom:12px"><div class="nc-meta">${catBadge(n.category)}<span class="nc-date">${fmts(n.date)}</span></div><div class="nc-title" style="font-size:15px">${esc(n.title)}</div><div class="nc-body" style="font-size:13px;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;overflow:hidden">${esc(n.content)}</div></div>`).join('')
    ||'<div class="empty"><span class="empty-icon">📄</span>No news yet.</div>';
}
function renderAdmNews(){
  const el=document.getElementById('adm-news');
  el.innerHTML=NEWS.length?NEWS.map(n=>`<div class="ar"><div><strong>${esc(n.title)}</strong><small>${catBadge(n.category)} ${fmt(n.date)}</small></div><button class="btn btn-r btn-sm" onclick="delNews('${n.id}')">Delete</button></div>`).join('')
    :'<div style="color:var(--muted);font-size:13px">No news items.</div>';
}
async function postNews(){
  const title=document.getElementById('adm-nwt').value.trim();
  const cat=document.getElementById('adm-nwc').value;
  const date=document.getElementById('adm-nwd').value||today();
  const content=document.getElementById('adm-nwb').value.trim();
  if(!title||!content){toast('Title and content required','er');return;}
  const r=await POST('/api/news',{title,category:cat,date,content});
  if(r&&r.id){['adm-nwt','adm-nwb'].forEach(id=>document.getElementById(id).value='');toast('Published!','ok');loadNews();}
  else if(r&&r.error) toast(r.error,'er');
}
async function delNews(id){ if(!confirm('Delete this news item?'))return; await DEL('/api/news/'+id); toast('Deleted'); loadNews(); }

// ── EVENTS ───────────────────────────────────────────────────────
let _evtF='all';
function evtFilter(f){
  _evtF=f;
  ['all','upcoming','past'].forEach(x=>{ const b=document.getElementById('ef-'+x); if(b) b.className='btn '+(x===f?'btn-s':'btn-gh'); });
  renderEvts();
}
function renderEvts(){
  let list=[...EVTS];
  if(_evtF==='upcoming') list=list.filter(e=>e.date>=today());
  if(_evtF==='past')     list=list.filter(e=>e.date<today());
  list.sort((a,b)=>a.date.localeCompare(b.date));
  const el=document.getElementById('evts-list');
  el.innerHTML=list.length?list.map(e=>evtCard(e,true)).join(''):'<div class="empty"><span class="empty-icon">📅</span>No events found.</div>';
}
function renderDashEvts(){
  const list=EVTS.filter(e=>e.date>=today()).sort((a,b)=>a.date.localeCompare(b.date)).slice(0,3);
  document.getElementById('dash-evts').innerHTML=list.length?list.map(e=>evtCard(e,false)).join(''):'<div class="empty"><span class="empty-icon">📅</span>No upcoming events.</div>';
}
function renderAdmEvts(){
  const el=document.getElementById('adm-evts');
  el.innerHTML=EVTS.length?EVTS.map(e=>`<div class="ar"><div><strong>${esc(e.name)}</strong><small>${fmt(e.date)} at ${e.time} — ${e.participants.length}/${e.maxParticipants} registered</small></div><button class="btn btn-r btn-sm" onclick="delEvent('${e.id}')">Delete</button></div>`).join('')
    :'<div style="color:var(--muted);font-size:13px">No events.</div>';
}

function evtCard(e, showReg){
  const up=e.date>=today(), full=e.participants.length>=e.maxParticipants;
  const pct=Math.min(100,Math.round(e.participants.length/e.maxParticipants*100));
  const myLabel=me?me.name+' (Room '+me.room+')':'';
  const registered=e.participants.includes(myLabel);
  const rid='reg-'+e.id;
  return`<div class="card ec${!up?' past':''}">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:6px">
      <div class="ec-name">${esc(e.name)}</div>
      ${up?(full?'<span class="badge bf">Full</span>':'<span class="badge bu">Upcoming</span>'):'<span class="badge bp">Past</span>'}
    </div>
    <div class="ec-meta">
      <span>📅 ${fmt(e.date)}</span><span>🕐 ${e.time}</span><span>📍 ${esc(e.location)}</span>
    </div>
    <div class="ec-desc">${esc(e.description)}</div>
    <div class="ec-foot">
      <span style="font-size:13px;color:var(--muted)">${e.participants.length}/${e.maxParticipants} participants
        <span class="cap-bar"><span class="cap-fill${full?' full':''}" style="width:${pct}%"></span></span>
      </span>
      ${up&&showReg?`<button class="btn btn-sm ${registered?'btn-gh':'btn-g'}" onclick="toggleReg('${rid}')">${registered?'Manage Registration':'Register'}</button>`:''}
    </div>
    ${up&&showReg?`<div class="reg-box" id="${rid}">
      <div style="font-size:13px;color:var(--muted);margin-bottom:10px">
        Registering as: <strong style="color:var(--slate)">${esc(myLabel)}</strong>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${!registered&&!full?`<button class="btn btn-g btn-sm" onclick="doRegEvt('${e.id}',false)">✓ Confirm</button>`:''}
        ${registered?`<button class="btn btn-gh btn-sm" onclick="doRegEvt('${e.id}',true)">✕ Cancel Registration</button>`:''}
      </div>
    </div>`:''}
  </div>`;
}
function toggleReg(id){ const el=document.getElementById(id); if(el) el.classList.toggle('open'); }

async function doRegEvt(id, cancel){
  const r=await POST('/api/events/'+id+'/register',{cancel});
  if(r&&r.id){ toast(cancel?'Registration cancelled':'Registered!','ok'); loadEvts(); }
  else if(r&&r.error) toast(r.error,'er');
}
async function createEvent(){
  const name=document.getElementById('adm-en').value.trim();
  const date=document.getElementById('adm-ed').value;
  const time=document.getElementById('adm-et').value||'18:00';
  const loc=document.getElementById('adm-el').value.trim()||'TBD';
  const max=parseInt(document.getElementById('adm-em').value)||20;
  const desc=document.getElementById('adm-edesc').value.trim();
  if(!name||!date){toast('Name and date required','er');return;}
  const r=await POST('/api/events',{name,date,time,location:loc,maxParticipants:max,description:desc});
  if(r&&r.id){['adm-en','adm-ed','adm-et','adm-el','adm-em','adm-edesc'].forEach(id=>document.getElementById(id).value='');toast('Event created!','ok');loadEvts();}
  else if(r&&r.error) toast(r.error,'er');
}
async function delEvent(id){ if(!confirm('Delete event?'))return; await DEL('/api/events/'+id); toast('Deleted'); loadEvts(); }

// ── LAUNDRY ──────────────────────────────────────────────────────
const SLOTS=['07:00','08:00','09:00','10:00','11:00','12:00','13:00','14:00','15:00','16:00','17:00','18:00','19:00','20:00','21:00','22:00'];

function selMachine(btn){
  document.querySelectorAll('.mt').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active'); selM=btn.dataset.m; renderSlots();
}
function renderSlots(){
  const date=document.getElementById('lb-date').value;
  const el=document.getElementById('lb-slots');
  if(!date){el.innerHTML='<div style="color:var(--muted);font-size:13px">Choose a date above.</div>';return;}
  const taken=LND.filter(b=>b.machineId===selM&&b.date===date).map(b=>b.slot);
  el.innerHTML=SLOTS.map(s=>{
    const t=taken.includes(s), sel=s===selSlot;
    return`<div class="slot${t?' taken':sel?' sel':''}" onclick="${t?'':'selectSlot(this,\''+s+'\')'}">${s}${t?'<br><small style="font-size:10px">Taken</small>':''}</div>`;
  }).join('');
}
function selectSlot(el,s){
  selSlot=s; document.getElementById('lb-slot').value=s;
  document.querySelectorAll('.slot').forEach(x=>x.classList.remove('sel'));
  el.classList.add('sel');
}
async function bookLaundry(){
  const date=document.getElementById('lb-date').value;
  const slot=document.getElementById('lb-slot').value;
  if(!date||!slot){toast('Please select a date and time slot','er');return;}
  const r=await POST('/api/laundry',{machineId:selM,date,slot});
  if(r&&r.id){selSlot='';document.getElementById('lb-slot').value='';toast('Booked!','ok');loadLnd();}
  else if(r&&r.error) toast(r.error,'er');
}
function renderLnd(){
  const tbody=document.getElementById('lnd-tbody');
  const sorted=[...LND].sort((a,b)=>a.date.localeCompare(b.date)||a.slot.localeCompare(b.slot));
  tbody.innerHTML=sorted.length?sorted.map(b=>{
    const mine=me&&(b.userId===me.id||me.role==='admin');
    return`<tr><td>${esc(b.name)}</td><td>${esc(b.room)}</td><td>${esc(b.machineId)}</td><td>${fmts(b.date)}</td><td>${b.slot}</td>
      <td>${mine?`<button class="btn btn-r btn-sm" onclick="cancelLnd('${b.id}')">Cancel</button>`:''}</td></tr>`;
  }).join(''):'<tr><td class="tbl-empty" colspan="6">No reservations yet.</td></tr>';
  renderSlots();
}
function renderAdmLnd(){
  const tbody=document.getElementById('adm-lnd');
  const sorted=[...LND].sort((a,b)=>a.date.localeCompare(b.date));
  tbody.innerHTML=sorted.length?sorted.map(b=>`<tr><td>${esc(b.name)}</td><td>${esc(b.room)}</td><td>${esc(b.machineId)}</td><td>${fmts(b.date)}</td><td>${b.slot}</td><td><button class="btn btn-r btn-sm" onclick="cancelLnd('${b.id}')">Del</button></td></tr>`).join('')
    :'<tr><td class="tbl-empty" colspan="6">No bookings.</td></tr>';
}
async function cancelLnd(id){ if(!confirm('Cancel this booking?'))return; await DEL('/api/laundry/'+id); toast('Cancelled'); loadLnd(); }

// ── EQUIPMENT ────────────────────────────────────────────────────
async function bookEquip(){
  const item=document.getElementById('eq-item').value;
  const date=document.getElementById('eq-date').value||today();
  const startTime=document.getElementById('eq-start').value||'';
  const endTime=document.getElementById('eq-end').value||'';
  const r=await POST('/api/equip',{item,date,startTime,endTime});
  if(r&&r.id){toast('Equipment booked! Max 1 hour — return after use.','ok');loadEq();}
  else if(r&&r.error) toast(r.error,'er');
}

// Equipment icons
const EQUIP_ICONS={'Vacuum Cleaner':'🧹','Ladder':'🪜','Power Drill':'🔧','Ironing Board':'👔'};
const ALL_EQUIP=['Vacuum Cleaner','Ladder','Power Drill','Ironing Board'];

function renderEquipBoard(){
  const el=document.getElementById('equip-board');
  if(!el) return;
  const td=today();
  el.innerHTML=ALL_EQUIP.map(item=>{
    const bookings=EQ.filter(b=>b.item===item&&b.date===td);
    const inUse=bookings.length>0;
    const icon=EQUIP_ICONS[item]||'📦';
    return`<div style="background:var(--parchment);border:2px solid ${inUse?'var(--red)':'var(--green)'};border-radius:var(--r2);padding:18px 16px;box-shadow:0 2px 10px var(--shadow);transition:border .2s">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
        <span style="font-size:26px">${icon}</span>
        <div>
          <div style="font-family:var(--serif);font-size:15px;font-weight:600;color:var(--slate)">${item}</div>
          <div style="display:inline-flex;align-items:center;gap:5px;margin-top:3px;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;background:${inUse?'rgba(185,84,80,.12)':'rgba(74,124,89,.13)'};color:${inUse?'var(--red)':'var(--green)'}">
            <span style="width:7px;height:7px;border-radius:50%;background:${inUse?'var(--red)':'var(--green)'};display:inline-block"></span>
            ${inUse?'IN USE':'AVAILABLE'}
          </div>
        </div>
      </div>
      ${inUse?bookings.map(b=>`
        <div style="border-top:1px solid var(--border);padding-top:9px;font-size:12px;line-height:1.7">
          <div style="font-weight:600;color:var(--slate)">👤 ${esc(b.name)}</div>
          <div style="color:var(--muted)">🚪 Room ${esc(b.room)}</div>
          ${b.startTime&&b.startTime!=='—'?`<div style="color:var(--muted)">🕐 ${esc(b.startTime)}${b.endTime&&b.endTime!=='—'?' → '+esc(b.endTime):''}</div>`:''}
        </div>`).join('')
      :'<div style="font-size:12px;color:var(--muted);padding-top:6px;border-top:1px solid var(--border)">No bookings today</div>'}
    </div>`;
  }).join('');
}

function renderEq(){
  renderEquipBoard();
  const tbody=document.getElementById('eq-tbody');
  const sorted=[...EQ].sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
  tbody.innerHTML=sorted.length?sorted.map(b=>{
    const mine=me&&(b.userId===me.id||me.role==='admin');
    return`<tr>
      <td>${esc(b.name)}</td><td>Room ${esc(b.room)}</td><td>${EQUIP_ICONS[b.item]||'📦'} ${esc(b.item)}</td>
      <td>${fmts(b.date)}</td>
      <td style="color:var(--muted);font-size:13px">${b.startTime&&b.startTime!=='—'?esc(b.startTime):'—'}</td>
      <td style="color:var(--muted);font-size:13px">${b.endTime&&b.endTime!=='—'?esc(b.endTime):'—'}</td>
      <td>${mine?`<button class="btn btn-r btn-sm" onclick="cancelEq('${b.id}')">Cancel</button>`:''}</td>
    </tr>`;
  }).join(''):'<tr><td class="tbl-empty" colspan="7">No bookings yet.</td></tr>';
}

function renderAdmEq(){
  const tbody=document.getElementById('adm-eq');
  const sorted=[...EQ].sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
  tbody.innerHTML=sorted.length?sorted.map(b=>`<tr>
    <td>${esc(b.name)}</td><td>Room ${esc(b.room)}</td><td>${esc(b.item)}</td>
    <td>${fmts(b.date)}</td>
    <td style="font-size:12px;color:var(--muted)">${b.startTime&&b.startTime!=='—'?esc(b.startTime):'—'}</td>
    <td style="font-size:12px;color:var(--muted)">${b.endTime&&b.endTime!=='—'?esc(b.endTime):'—'}</td>
    <td><button class="btn btn-r btn-sm" onclick="cancelEq('${b.id}')">Del</button></td>
  </tr>`).join(''):'<tr><td class="tbl-empty" colspan="7">No bookings.</td></tr>';
}
async function cancelEq(id){ if(!confirm('Cancel?'))return; await DEL('/api/equip/'+id); toast('Cancelled'); loadEq(); }


// ── ADMIN: USERS ─────────────────────────────────────────────────
function renderAdmUsers(users){
  const tbody=document.getElementById('adm-users');
  tbody.innerHTML=users.length?users.map(u=>`<tr>
    <td>${esc(u.name)}</td><td>${esc(u.room)}</td><td>${esc(u.username)}</td>
    <td style="font-size:12px;color:var(--muted)">${esc(u.email||'—')}</td>
    <td style="font-size:12px;color:var(--muted)">${esc(u.phone||'—')}</td>
    <td><span class="badge ${u.role==='admin'?'bg':'bu'}">${u.role}</span></td>
    <td style="font-size:12px;color:var(--muted)">${(u.createdAt||'').split('T')[0]}</td>
    <td>${u.role!=='admin'?`<button class="btn btn-r btn-sm" onclick="delUser('${u.id}')">Remove</button>`:''}</td>
  </tr>`).join(''):'<tr><td class="tbl-empty" colspan="8">No users.</td></tr>';
}
async function delUser(id){
  if(!confirm('Remove this resident?'))return;
  const r=await DEL('/api/users/'+id);
  if(r&&r.success){toast('Removed','ok');loadAdmUsers();}
  else if(r&&r.error) toast(r.error,'er');
}

// ── NAVIGATION ───────────────────────────────────────────────────
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  const b=document.querySelector('[data-page="'+name+'"]');
  if(b) b.classList.add('active');
  window.scrollTo(0,0);
  if(name==='admin'){renderAdmNews();renderAdmEvts();renderAdmNotices();renderAdmLnd();renderAdmEq();loadAdmUsers();}
}

// ── TOAST ────────────────────────────────────────────────────────
function toast(msg,type=''){
  const el=document.createElement('div');
  el.className='toast'+(type?' '+type:'');
  el.innerHTML=(type==='ok'?'<span>✓</span>':type==='er'?'<span>✕</span>':'')+`<span>${msg}</span>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>el.remove(),3500);
}

// ── UTILS ────────────────────────────────────────────────────────
function esc(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

// ── DIGITAL CLOCK ────────────────────────────────────────────────
function startClock(){
  function tick(){
    const now=new Date();
    const t=now.toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'});
    const d=now.toLocaleDateString('en-GB',{weekday:'long',day:'numeric',month:'long',year:'numeric'});
    const ct=document.getElementById('clock-time');
    const cd=document.getElementById('clock-date');
    if(ct) ct.textContent=t;
    if(cd) cd.textContent=d;
  }
  tick();
  setInterval(tick,1000);
}

// ── MINI CALENDAR ─────────────────────────────────────────────────
let calYear=new Date().getFullYear(), calMonth=new Date().getMonth();

function calNav(dir){
  calMonth+=dir;
  if(calMonth>11){calMonth=0;calYear++;}
  if(calMonth<0){calMonth=11;calYear--;}
  renderMiniCal();
}

function renderMiniCal(){
  const events=window._allEvents||[];
  // Build set of event dates this month: "YYYY-MM-DD"
  const eventDates={};
  events.forEach(e=>{
    if(e.date) {
      eventDates[e.date]=eventDates[e.date]||[];
      eventDates[e.date].push(e);
    }
  });

  const today=new Date();
  const todayStr=today.toISOString().split('T')[0];
  const monthNames=['January','February','March','April','May','June','July','August','September','October','November','December'];
  const label=document.getElementById('cal-month-label');
  if(label) label.textContent=monthNames[calMonth]+' '+calYear;

  const grid=document.getElementById('cal-grid');
  if(!grid) return;

  // Day-of-week headers
  const dows=['Mo','Tu','We','Th','Fr','Sa','Su'];
  let html=dows.map(d=>`<div class="mini-cal-dow">${d}</div>`).join('');

  // First day of month (0=Sun…6=Sat), convert to Mon-based
  const first=new Date(calYear,calMonth,1).getDay();
  const startOffset=(first===0)?6:first-1;
  const daysInMonth=new Date(calYear,calMonth+1,0).getDate();
  const prevDays=new Date(calYear,calMonth,0).getDate();

  // Previous month padding
  for(let i=startOffset-1;i>=0;i--){
    html+=`<div class="cal-day other">${prevDays-i}</div>`;
  }

  // Current month days
  for(let d=1;d<=daysInMonth;d++){
    const ds=calYear+'-'+(String(calMonth+1).padStart(2,'0'))+'-'+(String(d).padStart(2,'0'));
    const isToday=ds===todayStr;
    const hasEv=!!eventDates[ds];
    let cls='cal-day'+(isToday?' today':'')+(hasEv?' has-event':'');
    const title=hasEv?eventDates[ds].map(e=>e.name).join(', '):'';
    html+=`<div class="${cls}" title="${esc(title)}" onclick="calDayClick('${ds}')">${d}</div>`;
  }

  // Next month padding
  const totalCells=Math.ceil((startOffset+daysInMonth)/7)*7;
  const after=totalCells-(startOffset+daysInMonth);
  for(let i=1;i<=after;i++) html+=`<div class="cal-day other">${i}</div>`;

  grid.innerHTML=html;

  // Show events for today or selected day
  const sel=window._calSelected||todayStr;
  renderCalEvents(sel,eventDates);
}

let _calSelected=null;
function calDayClick(ds){
  window._calSelected=ds;
  const events=window._allEvents||[];
  const eventDates={};
  events.forEach(e=>{ if(e.date){eventDates[e.date]=eventDates[e.date]||[];eventDates[e.date].push(e);} });
  renderCalEvents(ds,eventDates);
}

function renderCalEvents(ds,eventDates){
  const el=document.getElementById('cal-event-list');
  if(!el) return;
  const evs=eventDates[ds]||[];
  const d=new Date(ds+'T12:00:00');
  const label=d.toLocaleDateString('en-GB',{weekday:'long',day:'numeric',month:'long'});
  if(!evs.length){
    el.innerHTML=`<div style="font-size:12px;color:var(--muted)">${label} — no events</div>`;
    return;
  }
  el.innerHTML=`<div style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--muted);margin-bottom:6px">${label}</div>`+
    evs.map(e=>`<div class="cal-event-item" onclick="showPage('events')">
      <div class="cal-event-dot"></div>
      <div><div style="font-weight:600;color:var(--slate)">${esc(e.name)}</div>
      <div style="color:var(--muted);font-size:11px">${esc(e.time_||'')}${e.location?' · '+esc(e.location):''}</div></div>
    </div>`).join('');
}

// ── INIT ─────────────────────────────────────────────────────────
checkExistingSession();
</script>
</body>
</html>
)HTMLEOF";

// ═══════════════════════════════════════════════════════════════════
//  §13  main()
// ═══════════════════════════════════════════════════════════════════
int main(int argc, char** argv){
    signal(SIGPIPE, SIG_IGN);

    int port = 3000;
    if(argc>1) port=std::atoi(argv[1]);

    // Get Postgres URL from environment
    const char* dbUrl=std::getenv("DATABASE_URL");
    if(!dbUrl){ std::cerr<<"WARNING: DATABASE_URL not set — data will not persist!\n"; dbUrl=""; }

    std::cout<<"\n╔══════════════════════════════════════════╗\n";
    std::cout<<"║   Residence Management System  (C++)     ║\n";
    std::cout<<"╠══════════════════════════════════════════╣\n";

    DB       db;
    Sessions sessions;
    SSEBroker sse;
    Mailer   mailer;

    std::cout<<"  Loading database…\n";
    db.load(dbUrl);
    mailer.init();

    Server srv;
    // ── Routes (inlined) ──────────────────────────────────────────

    // helper: get authenticated user (MUST be called with db.mtx held)
    auto auth=[&](const Req& req, Res& res) -> User* {
        auto uid=sessions.getUid(getToken(req));
        if(uid.empty()){ res.err(401,"Please log in."); return nullptr; }
        User* u=db.findUser(uid);
        if(!u){ res.err(401,"Session expired."); return nullptr; }
        return u;
    };
    // helper: broadcast events array
    auto bcEvents=[&](){
        auto list=db.events;
        std::sort(list.begin(),list.end(),[](auto&a,auto&b){return a.date<b.date;});
        sse.broadcast("events",toJArr(list).dump());
    };
    auto bcLaundry=[&](){ sse.broadcast("laundry",toJArr(db.laundry).dump()); };
    auto bcEquip  =[&](){ sse.broadcast("equip",  toJArr(db.equip).dump());   };
    auto bcNotices=[&](){
        Json a=Json::array();
        for(auto&n:db.notices) if(n.active) a.push(toJ(n));
        sse.broadcast("notices",a.dump());
    };

    // ── SSE ───────────────────────────────────────────────────────
    srv.sse("/api/stream",[&](int fd, const Req& req){
        auto uid=sessions.getUid(getToken(req));
        // check auth
        {
            std::lock_guard<std::mutex> lk(db.mtx);
            if(uid.empty()||!db.findUser(uid)){
                std::string r="HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                ::send(fd,r.c_str(),r.size(),MSG_NOSIGNAL); close(fd); return;
            }
        }
        std::string hdr="HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/event-stream\r\n"
                        "Cache-Control: no-cache\r\n"
                        "Access-Control-Allow-Origin: *\r\n"
                        "Connection: keep-alive\r\n\r\n"
                        ": connected\n\n";
        ::send(fd,hdr.c_str(),hdr.size(),MSG_NOSIGNAL);
        sse.add(fd);
        // keep thread alive until client disconnects (detected on next failed send)
        while(true){
            char tmp; int n=recv(fd,&tmp,1,MSG_PEEK);
            if(n==0||n<0) break;
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
        sse.remove(fd); close(fd);
    });

    // ── AUTH: register ────────────────────────────────────────────
    srv.route("POST","/api/auth/register",[&](const Req& req, Res& res){
        auto body=parseJson(req.body);
        auto name=body["name"].asStr(), room=body["room"].asStr();
        auto uname=body["username"].asStr(), pw=body["password"].asStr();
        auto email=body["email"].asStr(), phone=body["phone"].asStr();
        if(name.empty()||room.empty()||uname.empty()||pw.empty())
            { res.err(400,"Name, room number, username, and password are all required."); return; }
        if(pw.size()<6){ res.err(400,"Password must be at least 6 characters."); return; }
        {
            std::lock_guard<std::mutex> lk(db.mtx);
            if(db.findByUsername(uname)){ res.err(409,"That username is already taken."); return; }
            User u; u.id=makeUID(); u.name=name; u.room=room; u.username=uname;
            u.email=email; u.phone=phone;
            u.salt=randomHex(16); u.hash=hashPw(pw,u.salt); u.role="resident"; u.createdAt=nowISO();
            db.users.push_back(u); db.save();
            auto tok=sessions.create(u.id);
            Json r=Json::object(); r["token"]=Json(tok); r["user"]=toJ(u);
            res.json(r.dump());
            // welcome email
            if(!email.empty())
                mailer.sendAsync(email,name,"Welcome to the Residence Portal",
                    "Hi "+name+",\n\n"
                    "Welcome to the Residence Portal! Your account has been created.\n\n"
                    "Room: "+room+"\nUsername: "+uname+"\n\n"
                    "You can access the portal at any time to book laundry, equipment, and view events.\n\n"
                    "Best regards,\nResidence Management");
        }
    });

    // ── AUTH: login ───────────────────────────────────────────────
    srv.route("POST","/api/auth/login",[&](const Req& req, Res& res){
        auto body=parseJson(req.body);
        auto uname=body["username"].asStr(), pw=body["password"].asStr();
        if(uname.empty()||pw.empty()){ res.err(400,"Username and password required."); return; }
        std::lock_guard<std::mutex> lk(db.mtx);
        User* u=db.findByUsername(uname);
        if(!u||hashPw(pw,u->salt)!=u->hash){ res.err(401,"Incorrect username or password."); return; }
        auto tok=sessions.create(u->id);
        Json r=Json::object(); r["token"]=Json(tok); r["user"]=toJ(*u);
        res.json(r.dump());
    });

    // ── AUTH: logout ──────────────────────────────────────────────
    srv.route("POST","/api/auth/logout",[&](const Req& req, Res& res){
        sessions.remove(getToken(req));
        res.json("{\"success\":true}");
    });

    // ── AUTH: me ──────────────────────────────────────────────────
    srv.route("GET","/api/auth/me",[&](const Req& req, Res& res){
        auto uid=sessions.getUid(getToken(req));
        std::lock_guard<std::mutex> lk(db.mtx);
        User* u=db.findUser(uid);
        if(!u){ res.err(401,"Not logged in."); return; }
        res.json(toJ(*u).dump());
    });

    // ── USERS (admin) ─────────────────────────────────────────────
    srv.route("GET","/api/users",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        res.json(toJArr(db.users).dump());
    });
    srv.route("DELETE","/api/users/:id",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto id=req.params.at("id");
        if(id==me->id){ res.err(400,"Cannot delete your own account."); return; }
        auto& v=db.users;
        v.erase(std::remove_if(v.begin(),v.end(),[&](auto&u){return u.id==id;}),v.end());
        db.save(); res.json("{\"success\":true}");
    });

    // ── NOTICES ───────────────────────────────────────────────────
    srv.route("GET","/api/notices",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        Json a=Json::array(); for(auto&n:db.notices) if(n.active) a.push(toJ(n));
        res.json(a.dump());
    });
    srv.route("POST","/api/notices",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto body=parseJson(req.body);
        Notice n; n.id=makeUID(); n.text=body["text"].asStr(); n.urgent=body["urgent"].asBool(); n.active=true;
        db.notices.push_back(n); db.save(); bcNotices();
        res.json(toJ(n).dump());
        // broadcast to all residents with email
        std::string subj=n.urgent?"⚠ Urgent Notice — Residence Portal":"📢 New Notice — Residence Portal";
        std::string urgPfx=n.urgent?"[URGENT] ":"";
        std::string emailBody="A new notice has been posted:\n\n"+urgPfx+n.text+
            "\n\nView the portal for more details.\n\nResidence Management";
        mailer.broadcast(db.users,subj,emailBody);
    });
    srv.route("DELETE","/api/notices/:id",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto id=req.params.at("id");
        for(auto&n:db.notices) if(n.id==id) n.active=false;
        db.save(); bcNotices(); res.json("{\"success\":true}");
    });

    // ── NEWS ──────────────────────────────────────────────────────
    srv.route("GET","/api/news",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto list=db.news;
        std::sort(list.begin(),list.end(),[](auto&a,auto&b){return b.date<a.date;});
        res.json(toJArr(list).dump());
    });
    srv.route("POST","/api/news",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto body=parseJson(req.body);
        auto title=body["title"].asStr(), content=body["content"].asStr();
        if(title.empty()||content.empty()){ res.err(400,"Title and content required."); return; }
        NewsItem it; it.id=makeUID(); it.title=title;
        it.date=body["date"].asStr().empty()?todayStr():body["date"].asStr();
        it.category=body["category"].asStr().empty()?"General":body["category"].asStr();
        it.content=content;
        db.news.insert(db.news.begin(),it); db.save();
        sse.broadcast("news",toJ(it).dump());
        res.json(toJ(it).dump());
    });
    srv.route("DELETE","/api/news/:id",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto id=req.params.at("id");
        auto& v=db.news;
        v.erase(std::remove_if(v.begin(),v.end(),[&](auto&x){return x.id==id;}),v.end());
        db.save(); sse.broadcast("news-deleted","{\"id\":\""+id+"\"}");
        res.json("{\"success\":true}");
    });

    // ── EVENTS ────────────────────────────────────────────────────
    srv.route("GET","/api/events",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto list=db.events;
        std::sort(list.begin(),list.end(),[](auto&a,auto&b){return a.date<b.date;});
        res.json(toJArr(list).dump());
    });
    srv.route("POST","/api/events",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto body=parseJson(req.body);
        if(body["name"].asStr().empty()||body["date"].asStr().empty())
            { res.err(400,"Name and date required."); return; }
        Event e; e.id=makeUID(); e.name=body["name"].asStr(); e.date=body["date"].asStr();
        e.time_=body["time"].asStr().empty()?"00:00":body["time"].asStr();
        e.description=body["description"].asStr();
        e.location=body["location"].asStr().empty()?"TBD":body["location"].asStr();
        e.maxParticipants=body["maxParticipants"].asInt()?body["maxParticipants"].asInt():20;
        e.createdAt=todayStr();
        db.events.push_back(e); db.save(); bcEvents();
        res.json(toJ(e).dump());
    });
    srv.route("DELETE","/api/events/:id",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        if(me->role!="admin"){ res.err(403,"Admin only."); return; }
        auto id=req.params.at("id");
        auto& v=db.events;
        v.erase(std::remove_if(v.begin(),v.end(),[&](auto&e){return e.id==id;}),v.end());
        db.save(); bcEvents(); res.json("{\"success\":true}");
    });
    // Event registration / cancellation
    srv.route("POST","/api/events/:id/register",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto id=req.params.at("id");
        Event* e=db.findEvent(id);
        if(!e){ res.err(404,"Event not found."); return; }
        auto body=parseJson(req.body);
        std::string label=me->name+" (Room "+me->room+")";
        if(body["cancel"].asBool()){
            auto& p=e->participants;
            p.erase(std::remove(p.begin(),p.end(),label),p.end());
        } else {
            if((int)e->participants.size()>=e->maxParticipants)
                { res.err(400,"This event is full."); return; }
            if(std::find(e->participants.begin(),e->participants.end(),label)==e->participants.end())
                e->participants.push_back(label);
        }
        db.save(); bcEvents(); res.json(toJ(*e).dump());
    });

    // ── LAUNDRY ───────────────────────────────────────────────────
    srv.route("GET","/api/laundry",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        res.json(toJArr(db.laundry).dump());
    });
    srv.route("POST","/api/laundry",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto body=parseJson(req.body);
        auto mid=body["machineId"].asStr(), date=body["date"].asStr(), slot=body["slot"].asStr();
        if(mid.empty()||date.empty()||slot.empty())
            { res.err(400,"Machine, date, and slot required."); return; }
        for(auto&b:db.laundry)
            if(b.machineId==mid&&b.date==date&&b.slot==slot)
                { res.err(409,"That slot is already booked."); return; }
        LaundryBk bk; bk.id=makeUID(); bk.name=me->name; bk.room=me->room;
        bk.userId=me->id; bk.machineId=mid; bk.date=date; bk.slot=slot; bk.createdAt=nowISO();
        db.laundry.push_back(bk); db.save(); bcLaundry();
        res.json(toJ(bk).dump());
        if(!me->email.empty())
            mailer.sendAsync(me->email,me->name,"🧺 Laundry Booking Confirmed",
                "Hi "+me->name+",\n\nYour laundry booking is confirmed:\n\n"
                "Machine: "+mid+"\nDate: "+date+"\nTime: "+slot+"\n\n"
                "Remember the 10-minute rule — move your laundry promptly after the cycle ends.\n\n"
                "Residence Management");
    });
    srv.route("DELETE","/api/laundry/:id",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto id=req.params.at("id");
        LaundryBk* bk=db.findLaundry(id);
        if(!bk){ res.err(404,"Not found."); return; }
        if(me->role!="admin"&&bk->userId!=me->id)
            { res.err(403,"You can only cancel your own bookings."); return; }
        auto& v=db.laundry;
        v.erase(std::remove_if(v.begin(),v.end(),[&](auto&b){return b.id==id;}),v.end());
        db.save(); bcLaundry(); res.json("{\"success\":true}");
    });

    // ── EQUIPMENT ─────────────────────────────────────────────────
    srv.route("GET","/api/equip",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        res.json(toJArr(db.equip).dump());
    });
    srv.route("POST","/api/equip",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto body=parseJson(req.body);
        auto item=body["item"].asStr(), date=body["date"].asStr();
        auto startTime=body["startTime"].asStr(), endTime=body["endTime"].asStr();
        if(item.empty()||date.empty()){ res.err(400,"Item and date required."); return; }
        if(startTime.empty()) startTime="—";
        if(endTime.empty())   endTime="—";
        for(auto&b:db.equip)
            if(b.userId==me->id&&b.item==item&&b.date==date)
                { res.err(409,"You already have a booking for this item today (max 1 hour/day)."); return; }
        EquipBk bk; bk.id=makeUID(); bk.name=me->name; bk.room=me->room;
        bk.userId=me->id; bk.item=item; bk.date=date;
        bk.startTime=startTime; bk.endTime=endTime;
        bk.duration=60; bk.createdAt=nowISO();
        db.equip.push_back(bk); db.save(); bcEquip();
        res.json(toJ(bk).dump());
        if(!me->email.empty())
            mailer.sendAsync(me->email,me->name,"🔧 Equipment Booking Confirmed",
                "Hi "+me->name+",\n\nYour equipment booking is confirmed:\n\n"
                "Item: "+item+"\nDate: "+date+"\nTime: "+startTime+" – "+endTime+"\n\n"
                "Please return the item promptly after use.\n\n"
                "Residence Management");
    });
    srv.route("DELETE","/api/equip/:id",[&](const Req& req, Res& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        User* me=auth(req,res); if(!me) return;
        auto id=req.params.at("id");
        EquipBk* bk=db.findEquip(id);
        if(!bk){ res.err(404,"Not found."); return; }
        if(me->role!="admin"&&bk->userId!=me->id)
            { res.err(403,"You can only cancel your own bookings."); return; }
        auto& v=db.equip;
        v.erase(std::remove_if(v.begin(),v.end(),[&](auto&b){return b.id==id;}),v.end());
        db.save(); bcEquip(); res.json("{\"success\":true}");
    });

    // ── end routes ─────────────────────────────────────────────
    srv.setHtml(FRONTEND);

    std::cout<<"╠══════════════════════════════════════════╣\n";
    std::cout<<"║  Open:    http://localhost:"<<port<<"           ║\n";
    std::cout<<"║  Network: http://<your-ip>:"<<port<<"          ║\n";
    std::cout<<"║  Admin:   username=admin  pw=admin123    ║\n";
    std::cout<<"║  Ctrl+C to stop                          ║\n";
    std::cout<<"╚══════════════════════════════════════════╝\n\n";

    srv.listen(port);
    return 0;
}
