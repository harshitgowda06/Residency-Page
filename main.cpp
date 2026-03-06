/*
 * ╔══════════════════════════════════════════════════════════════════╗
 * ║   Residence Management System — C++ Backend + Embedded Frontend ║
 * ║                                                                  ║
 * ║   Build:  g++ -std=c++17 -O2 -o residence main.cpp -lpthread    ║
 * ║   Run:    ./residence                                            ║
 * ║   Open:   http://localhost:3000                                  ║
 * ║                                                                  ║
 * ║   Default admin:  username=admin  password=admin123             ║
 * ║   Residents self-register with name, room number, password      ║
 * ╚══════════════════════════════════════════════════════════════════╝
 *
 *  Zero external dependencies — POSIX sockets + C++17 stdlib only.
 */

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <algorithm>
#include <chrono>
#include <random>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <stdexcept>

// ═══════════════════════════════════════════════════════════════════
//  SHA-256 (pure C++ — no OpenSSL header needed)
// ═══════════════════════════════════════════════════════════════════
namespace sha256_impl {
    static const uint32_t K[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
        0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
        0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
        0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
        0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
        0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    inline uint32_t rotr(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
    std::string hash(const std::string& msg) {
        uint32_t h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
        uint32_t h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
        std::vector<uint8_t> data(msg.begin(),msg.end());
        uint64_t bitlen = data.size()*8;
        data.push_back(0x80);
        while (data.size()%64 != 56) data.push_back(0);
        for (int i=7;i>=0;i--) data.push_back((bitlen>>(i*8))&0xFF);
        for (size_t chunk=0;chunk<data.size();chunk+=64){
            uint32_t w[64]={};
            for (int i=0;i<16;i++)
                w[i]=(data[chunk+i*4]<<24)|(data[chunk+i*4+1]<<16)|(data[chunk+i*4+2]<<8)|data[chunk+i*4+3];
            for (int i=16;i<64;i++){
                uint32_t s0=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3);
                uint32_t s1=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);
                w[i]=w[i-16]+s0+w[i-7]+s1;
            }
            uint32_t a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
            for (int i=0;i<64;i++){
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
        std::ostringstream oss;
        for (auto v:{h0,h1,h2,h3,h4,h5,h6,h7})
            oss<<std::hex<<std::setw(8)<<std::setfill('0')<<v;
        return oss.str();
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Hex helpers
// ═══════════════════════════════════════════════════════════════════
static std::string toHex(const std::string& s) {
    std::ostringstream o;
    for (unsigned char c : s) o << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return o.str();
}
static std::string randomHex(int bytes) {
    std::random_device rd;
    std::string out;
    for (int i=0;i<bytes;i++){
        std::ostringstream o;
        o<<std::hex<<std::setw(2)<<std::setfill('0')<<(rd()&0xFF);
        out+=o.str();
    }
    return out;
}
static std::string hashPassword(const std::string& pw, const std::string& salt) {
    // PBKDF2-lite: 10000 rounds of SHA-256(salt+password+iteration)
    std::string result = salt + pw;
    for (int i=0;i<10000;i++) result = sha256_impl::hash(result + std::to_string(i));
    return result;
}
static std::string makeToken() { return randomHex(32); }
static std::string makeUID() {
    static std::atomic<uint64_t> counter{0};
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    return toHex(std::to_string(now) + std::to_string(++counter));
}
static std::string todayStr() {
    auto t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    char buf[16];
    std::strftime(buf,sizeof(buf),"%Y-%m-%d",&tm);
    return buf;
}
static std::string nowISO() {
    auto t = std::time(nullptr);
    std::tm tm = *std::localtime(&t);
    char buf[32];
    std::strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%S",&tm);
    return buf;
}
static std::string dateOffset(int days) {
    std::time_t t = std::time(nullptr) + (std::time_t)days*86400;
    std::tm tm = *std::localtime(&t);
    char buf[16];
    std::strftime(buf,sizeof(buf),"%Y-%m-%d",&tm);
    return buf;
}

// ═══════════════════════════════════════════════════════════════════
//  Minimal JSON engine (same proven impl from MarketOS)
// ═══════════════════════════════════════════════════════════════════
struct Json {
    enum Type { NUL, BOOL, NUMBER, STRING, ARRAY, OBJECT };
    Type type=NUL; bool b=false; double n=0; std::string s;
    std::vector<Json> arr;
    std::vector<std::pair<std::string,Json>> obj;

    Json(){}
    Json(bool v):type(BOOL),b(v){}
    Json(double v):type(NUMBER),n(v){}
    Json(int v):type(NUMBER),n(v){}
    Json(long long v):type(NUMBER),n((double)v){}
    Json(const std::string& v):type(STRING),s(v){}
    Json(const char* v):type(STRING),s(v){}
    static Json array(){Json j;j.type=ARRAY;return j;}
    static Json object(){Json j;j.type=OBJECT;return j;}

    Json& operator[](const std::string& key){
        for(auto&p:obj)if(p.first==key)return p.second;
        obj.push_back({key,Json()});return obj.back().second;
    }
    const Json& operator[](const std::string& key)const{
        static Json nv;for(auto&p:obj)if(p.first==key)return p.second;return nv;
    }
    bool has(const std::string&k)const{for(auto&p:obj)if(p.first==k)return true;return false;}
    void set(const std::string&k,Json v){(*this)[k]=v;}
    void push(Json v){arr.push_back(v);}
    size_t size()const{return type==ARRAY?arr.size():obj.size();}
    bool asBool()const{return b;}
    double asDouble()const{return n;}
    long long asLong()const{return(long long)n;}
    std::string asString()const{return s;}

    std::string dump(int ind=0,int cur=0)const{
        std::string pad(cur,' '),ipad(cur+ind,' ');
        std::ostringstream o;
        switch(type){
            case NUL:o<<"null";break;
            case BOOL:o<<(b?"true":"false");break;
            case NUMBER:if(n==(long long)n)o<<(long long)n;else o<<std::fixed<<std::setprecision(4)<<n;break;
            case STRING:{o<<'"';for(char c:s){if(c=='"')o<<"\\\"";else if(c=='\\')o<<"\\\\";else if(c=='\n')o<<"\\n";else if(c=='\r')o<<"\\r";else if(c=='\t')o<<"\\t";else o<<c;}o<<'"';break;}
            case ARRAY:{o<<'[';if(ind)o<<'\n';for(size_t i=0;i<arr.size();i++){if(ind)o<<ipad;o<<arr[i].dump(ind,cur+ind);if(i+1<arr.size())o<<',';if(ind)o<<'\n';}if(ind)o<<pad;o<<']';break;}
            case OBJECT:{o<<'{';if(ind)o<<'\n';for(size_t i=0;i<obj.size();i++){if(ind)o<<ipad;o<<'"'<<obj[i].first<<'"'<<':';if(ind)o<<' ';o<<obj[i].second.dump(ind,cur+ind);if(i+1<obj.size())o<<',';if(ind)o<<'\n';}if(ind)o<<pad;o<<'}';break;}
        }
        return o.str();
    }
};

struct JsonParser{
    const std::string&src;size_t pos=0;
    JsonParser(const std::string&s):src(s){}
    void skipWS(){while(pos<src.size()&&isspace(src[pos]))pos++;}
    Json parse(){
        skipWS();if(pos>=src.size())return Json();
        char c=src[pos];
        if(c=='{')return parseObject();if(c=='[')return parseArray();
        if(c=='"')return parseString();
        if(c=='t'){pos+=4;return Json(true);}
        if(c=='f'){pos+=5;return Json(false);}
        if(c=='n'){pos+=4;return Json();}
        return parseNumber();
    }
    Json parseObject(){
        Json j=Json::object();pos++;skipWS();
        if(pos<src.size()&&src[pos]=='}'){pos++;return j;}
        while(pos<src.size()){
            skipWS();auto key=parseString().asString();
            skipWS();pos++;skipWS();
            j.set(key,parse());skipWS();
            if(pos<src.size()&&src[pos]==',')pos++;
            skipWS();if(pos<src.size()&&src[pos]=='}'){pos++;break;}
        }
        return j;
    }
    Json parseArray(){
        Json j=Json::array();pos++;skipWS();
        if(pos<src.size()&&src[pos]==']'){pos++;return j;}
        while(pos<src.size()){
            skipWS();j.push(parse());skipWS();
            if(pos<src.size()&&src[pos]==',')pos++;
            skipWS();if(pos<src.size()&&src[pos]==']'){pos++;break;}
        }
        return j;
    }
    Json parseString(){
        pos++;std::string out;
        while(pos<src.size()&&src[pos]!='"'){
            if(src[pos]=='\\'){pos++;if(pos>=src.size())break;
                char e=src[pos];
                if(e=='"')out+='"';else if(e=='\\')out+='\\';
                else if(e=='n')out+='\n';else if(e=='r')out+='\r';
                else if(e=='t')out+='\t';else out+=e;
            }else out+=src[pos];
            pos++;
        }
        pos++;return Json(out);
    }
    Json parseNumber(){
        size_t start=pos;
        if(pos<src.size()&&src[pos]=='-')pos++;
        while(pos<src.size()&&(isdigit(src[pos])||src[pos]=='.'||src[pos]=='e'||src[pos]=='E'||src[pos]=='+'||src[pos]=='-'))pos++;
        try{return Json(std::stod(src.substr(start,pos-start)));}catch(...){return Json();}
    }
};
Json parseJson(const std::string&s){JsonParser p(s);return p.parse();}

// ═══════════════════════════════════════════════════════════════════
//  Data models
// ═══════════════════════════════════════════════════════════════════
struct User {
    std::string id, name, room, username, hash, salt, role, createdAt;
};
struct Notice { std::string id, text; bool active=true, urgent=false; };
struct NewsItem { std::string id, title, date, category, content; };
struct Event {
    std::string id, name, date, time_, description, location, createdAt;
    int maxParticipants=20;
    std::vector<std::string> participants;
};
struct LaundryBooking  { std::string id, name, room, userId, machineId, date, slot, createdAt; };
struct EquipmentBooking{ std::string id, name, room, userId, item, date, createdAt; int duration=60; };

// ═══════════════════════════════════════════════════════════════════
//  Database
// ═══════════════════════════════════════════════════════════════════
class Database {
public:
    std::vector<User>             users;
    std::vector<Notice>           notices;
    std::vector<NewsItem>         news;
    std::vector<Event>            events;
    std::vector<LaundryBooking>   laundry;
    std::vector<EquipmentBooking> equipment;
    std::mutex mtx;
    std::string path;

    void load(const std::string& filepath) {
        path = filepath;
        std::ifstream f(filepath);
        if (!f.good()) { seed(); save(); return; }
        std::string content((std::istreambuf_iterator<char>(f)),{});
        if (content.empty()) { seed(); save(); return; }
        try {
            Json root = parseJson(content);
            // users
            for (auto& j : root["users"].arr) {
                User u;
                u.id=j["id"].asString(); u.name=j["name"].asString();
                u.room=j["room"].asString(); u.username=j["username"].asString();
                u.hash=j["hash"].asString(); u.salt=j["salt"].asString();
                u.role=j["role"].asString(); u.createdAt=j["createdAt"].asString();
                users.push_back(u);
            }
            // notices
            for (auto& j : root["notices"].arr) {
                Notice n; n.id=j["id"].asString(); n.text=j["text"].asString();
                n.active=j["active"].asBool(); n.urgent=j["urgent"].asBool();
                notices.push_back(n);
            }
            // news
            for (auto& j : root["news"].arr) {
                NewsItem it; it.id=j["id"].asString(); it.title=j["title"].asString();
                it.date=j["date"].asString(); it.category=j["category"].asString();
                it.content=j["content"].asString();
                news.push_back(it);
            }
            // events
            for (auto& j : root["events"].arr) {
                Event e; e.id=j["id"].asString(); e.name=j["name"].asString();
                e.date=j["date"].asString(); e.time_=j["time"].asString();
                e.description=j["description"].asString(); e.location=j["location"].asString();
                e.maxParticipants=(int)j["maxParticipants"].asLong(); e.createdAt=j["createdAt"].asString();
                for (auto& p : j["participants"].arr) e.participants.push_back(p.asString());
                events.push_back(e);
            }
            // laundry
            for (auto& j : root["laundry"].arr) {
                LaundryBooking b; b.id=j["id"].asString(); b.name=j["name"].asString();
                b.room=j["room"].asString(); b.userId=j["userId"].asString();
                b.machineId=j["machineId"].asString(); b.date=j["date"].asString();
                b.slot=j["slot"].asString(); b.createdAt=j["createdAt"].asString();
                laundry.push_back(b);
            }
            // equipment
            for (auto& j : root["equipment"].arr) {
                EquipmentBooking b; b.id=j["id"].asString(); b.name=j["name"].asString();
                b.room=j["room"].asString(); b.userId=j["userId"].asString();
                b.item=j["item"].asString(); b.date=j["date"].asString();
                b.duration=(int)j["duration"].asLong(); b.createdAt=j["createdAt"].asString();
                equipment.push_back(b);
            }
            ensureAdmin();
            std::cout << "  Database loaded. Users: " << users.size() << "\n";
        } catch(...) { users.clear(); news.clear(); events.clear(); notices.clear(); laundry.clear(); equipment.clear(); seed(); save(); }
    }

    void save() {
        Json root = Json::object();
        // users
        Json ju = Json::array();
        for (auto& u : users) {
            Json j=Json::object(); j["id"]=Json(u.id); j["name"]=Json(u.name); j["room"]=Json(u.room);
            j["username"]=Json(u.username); j["hash"]=Json(u.hash); j["salt"]=Json(u.salt);
            j["role"]=Json(u.role); j["createdAt"]=Json(u.createdAt); ju.push(j);
        }
        root["users"]=ju;
        // notices
        Json jn=Json::array();
        for (auto& n : notices) {
            Json j=Json::object(); j["id"]=Json(n.id); j["text"]=Json(n.text);
            j["active"]=Json(n.active); j["urgent"]=Json(n.urgent); jn.push(j);
        }
        root["notices"]=jn;
        // news
        Json jnw=Json::array();
        for (auto& it : news) {
            Json j=Json::object(); j["id"]=Json(it.id); j["title"]=Json(it.title);
            j["date"]=Json(it.date); j["category"]=Json(it.category); j["content"]=Json(it.content); jnw.push(j);
        }
        root["news"]=jnw;
        // events
        Json jev=Json::array();
        for (auto& e : events) {
            Json j=Json::object(); j["id"]=Json(e.id); j["name"]=Json(e.name);
            j["date"]=Json(e.date); j["time"]=Json(e.time_); j["description"]=Json(e.description);
            j["location"]=Json(e.location); j["maxParticipants"]=Json((long long)e.maxParticipants);
            j["createdAt"]=Json(e.createdAt);
            Json jp=Json::array(); for(auto&p:e.participants)jp.push(Json(p)); j["participants"]=jp;
            jev.push(j);
        }
        root["events"]=jev;
        // laundry
        Json jl=Json::array();
        for (auto& b : laundry) {
            Json j=Json::object(); j["id"]=Json(b.id); j["name"]=Json(b.name); j["room"]=Json(b.room);
            j["userId"]=Json(b.userId); j["machineId"]=Json(b.machineId); j["date"]=Json(b.date);
            j["slot"]=Json(b.slot); j["createdAt"]=Json(b.createdAt); jl.push(j);
        }
        root["laundry"]=jl;
        // equipment
        Json je=Json::array();
        for (auto& b : equipment) {
            Json j=Json::object(); j["id"]=Json(b.id); j["name"]=Json(b.name); j["room"]=Json(b.room);
            j["userId"]=Json(b.userId); j["item"]=Json(b.item); j["date"]=Json(b.date);
            j["duration"]=Json((long long)b.duration); j["createdAt"]=Json(b.createdAt); je.push(j);
        }
        root["equipment"]=je;
        std::ofstream f(path); f << root.dump(2);
    }

    User* findUser(const std::string& id) { for(auto&u:users)if(u.id==id)return&u; return nullptr; }
    User* findUserByUsername(const std::string& uname) {
        std::string l=uname; std::transform(l.begin(),l.end(),l.begin(),::tolower);
        for(auto&u:users){std::string ul=u.username;std::transform(ul.begin(),ul.end(),ul.begin(),::tolower);if(ul==l)return&u;}
        return nullptr;
    }
    User* findUserByRoom(const std::string& room) {
        std::string l=room; std::transform(l.begin(),l.end(),l.begin(),::tolower);
        for(auto&u:users){if(u.role=="admin")continue;std::string rl=u.room;std::transform(rl.begin(),rl.end(),rl.begin(),::tolower);if(rl==l)return&u;}
        return nullptr;
    }
    NewsItem* findNews(const std::string& id){for(auto&n:news)if(n.id==id)return&n;return nullptr;}
    Event* findEvent(const std::string& id){for(auto&e:events)if(e.id==id)return&e;return nullptr;}
    LaundryBooking* findLaundry(const std::string& id){for(auto&b:laundry)if(b.id==id)return&b;return nullptr;}
    EquipmentBooking* findEquipment(const std::string& id){for(auto&b:equipment)if(b.id==id)return&b;return nullptr;}

    void ensureAdmin() {
        if (findUserByUsername("admin")) return;
        User u;
        u.id=makeUID(); u.name="Management"; u.room="Admin"; u.username="admin";
        u.salt=randomHex(16); u.hash=hashPassword("admin123",u.salt);
        u.role="admin"; u.createdAt=nowISO();
        users.push_back(u); save();
        std::cout << "  Admin created: username=admin  password=admin123\n";
    }

    void seed() {
        users.clear(); news.clear(); events.clear(); notices.clear(); laundry.clear(); equipment.clear();
        ensureAdmin();

        notices.push_back({makeUID(),"Welcome to the Residence Portal — your central hub for news, events, and bookings.",true,false});
        notices.push_back({makeUID(),"The vacuum is currently missing. Please report if found.",true,true});

        auto addNews = [&](const std::string& title, const std::string& date, const std::string& cat, const std::string& content){
            NewsItem it; it.id=makeUID(); it.title=title; it.date=date; it.category=cat; it.content=content;
            news.push_back(it);
        };
        std::string td=todayStr(), p2=dateOffset(-14);
        addNews("New Freezer Coming Soon",                    td, "Kitchen",     "A third freezer is expected to arrive soon to accommodate the growing demand for frozen storage. More details will be shared once a delivery date is confirmed.");
        addNews("Kitchen Lockers Installation",               td, "Kitchen",     "Lockers for the kitchen are expected to be installed soon, providing dedicated secure storage for each resident's kitchen supplies.");
        addNews("Shelf & Drawer Allocation — Action Required",td, "Kitchen",     "Drawers and shelves are available for all residents inside the kitchen and in the lounge area. Residents must identify their desired space and contact Mostafa to reserve it.");
        addNews("Fridge Shelf System Now Active",             td, "Kitchen",     "Identified shelves inside the fridge are now in operation. All residents are reminded that their designated fridge shelves must be kept clean and tidy at all times.");
        addNews("Laundry Room Whiteboard Coming",             td, "Laundry",     "A whiteboard will be installed in the laundry room to improve communication and machine identification. Residents will be able to write their Name, Room Number, and Machine ID to track usage.");
        addNews("10-Minute Rule Reminder",                    td, "Laundry",     "The laundry room's 10-minute rule remains in effect. If your laundry has been sitting in a machine for more than 10 minutes after the cycle ends, another resident may move it.");
        addNews("Vacuum Cleaner Missing",                     td, "Maintenance", "The shared vacuum cleaner is currently unaccounted for. If you have it or know its location, please return it immediately or inform management.");
        addNews("Vacuum Usage Policy",                        td, "Maintenance", "Going forward, vacuum cleaner use will be limited to a maximum of 1 hour per day per resident. A booking system similar to the laundry room will be implemented shortly.");
        addNews("Report Maintenance Issues",                  td, "Maintenance", "Residents are encouraged to report all maintenance issues promptly, including broken light bulbs, missing hangers, or any damage to shared spaces.");
        addNews("Community Events Recap",                     p2, "General",     "Previous community events have had a strong positive impact on the residence atmosphere. More events will be announced soon.");

        auto addEvent = [&](const std::string& name, const std::string& date, const std::string& time_,
                            const std::string& desc, const std::string& loc, int maxP,
                            std::vector<std::string> parts={}) {
            Event e; e.id=makeUID(); e.name=name; e.date=date; e.time_=time_;
            e.description=desc; e.location=loc; e.maxParticipants=maxP;
            e.participants=parts; e.createdAt=td; events.push_back(e);
        };
        addEvent("Community Game Night",    dateOffset(7),  "19:00", "Join your neighbours for a relaxed evening of board games and card games. All skill levels welcome!", "Lounge Area", 15);
        addEvent("Shared Cooking Evening",  dateOffset(14), "18:30", "We cook together, we eat together. This month's theme is Mediterranean food.", "Kitchen", 10);
        addEvent("Building Welcome Gathering", dateOffset(-7),"18:00","The first official welcome gathering for all current residents.", "Lounge Area", 20, {"Room 101","Room 102","Room 103","Room 104","Room 105"});
    }
};

// ═══════════════════════════════════════════════════════════════════
//  Session store
// ═══════════════════════════════════════════════════════════════════
struct Session { std::string userId; long long expiresAt; };
class SessionStore {
    std::map<std::string,Session> store;
    // No internal mutex — callers must hold db.mtx
    static const long long TTL = 7LL*24*3600*1000; // 7 days ms
public:
    std::string create(const std::string& userId) {
        std::string token = makeToken();
        long long exp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + TTL;
        store[token] = {userId, exp};
        return token;
    }
    std::string getUserId(const std::string& token) {
        auto it = store.find(token);
        if (it == store.end()) return "";
        long long now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (now > it->second.expiresAt) { store.erase(it); return ""; }
        return it->second.userId;
    }
    void remove(const std::string& token) {
        store.erase(token);
    }
};

// ═══════════════════════════════════════════════════════════════════
//  SSE (Server-Sent Events) broker
// ═══════════════════════════════════════════════════════════════════
class SSEBroker {
    std::set<int> clients;
    std::mutex mtx;
public:
    void add(int fd) { std::lock_guard<std::mutex> lk(mtx); clients.insert(fd); }
    void remove(int fd) { std::lock_guard<std::mutex> lk(mtx); clients.erase(fd); }
    void broadcast(const std::string& event, const std::string& data) {
        std::string msg = "event: "+event+"\ndata: "+data+"\n\n";
        std::lock_guard<std::mutex> lk(mtx);
        std::vector<int> dead;
        for (int fd : clients) {
            if (send(fd, msg.c_str(), msg.size(), MSG_NOSIGNAL) <= 0) dead.push_back(fd);
        }
        for (int fd : dead) clients.erase(fd);
    }
};

// ═══════════════════════════════════════════════════════════════════
//  HTTP Server
// ═══════════════════════════════════════════════════════════════════
struct HttpRequest {
    std::string method, path, query, body;
    std::unordered_map<std::string,std::string> headers;
    std::unordered_map<std::string,std::string> params;
};
struct HttpResponse {
    int status=200; std::string statusText="OK";
    std::unordered_map<std::string,std::string> headers;
    std::string body;
    void json(const std::string& j){headers["Content-Type"]="application/json";body=j;}
    void html(const std::string& h){headers["Content-Type"]="text/html; charset=utf-8";body=h;}
    void err(int code,const std::string& msg){
        status=code; statusText=msg;
        headers["Content-Type"]="application/json";
        body="{\"error\":\""+msg+"\"}";
    }
    std::string build()const{
        std::ostringstream o;
        o<<"HTTP/1.1 "<<status<<" "<<statusText<<"\r\n";
        o<<"Access-Control-Allow-Origin: *\r\n";
        o<<"Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS\r\n";
        o<<"Access-Control-Allow-Headers: Content-Type,Authorization\r\n";
        o<<"Connection: close\r\n";
        for(auto&h:headers)o<<h.first<<": "<<h.second<<"\r\n";
        o<<"Content-Length: "<<body.size()<<"\r\n\r\n"<<body;
        return o.str();
    }
};

static std::string urlDecode(const std::string& s){
    std::string out; for(size_t i=0;i<s.size();i++){
        if(s[i]=='%'&&i+2<s.size()){out+=(char)std::stoi(s.substr(i+1,2),nullptr,16);i+=2;}
        else if(s[i]=='+')out+=' '; else out+=s[i];
    } return out;
}

class HttpServer {
    int serverFd=-1;
    std::atomic<bool> running{false};
    struct Route { std::string method, pattern; std::function<void(const HttpRequest&,HttpResponse&)> handler; };
    std::vector<Route> routes;
    std::string staticHtml;

    bool matchRoute(const Route& r, const std::string& method, const std::string& path,
                    std::unordered_map<std::string,std::string>& params) {
        if (r.method!=method && r.method!="*") return false;
        auto split=[](const std::string&s,char d){
            std::vector<std::string>v; std::istringstream ss(s); std::string t;
            while(std::getline(ss,t,d))if(!t.empty())v.push_back(t); return v;
        };
        auto rp=split(r.pattern,'/'), pp=split(path,'/');
        if(rp.size()!=pp.size())return false;
        params.clear();
        for(size_t i=0;i<rp.size();i++){
            if(rp[i][0]==':')params[rp[i].substr(1)]=pp[i];
            else if(rp[i]!=pp[i])return false;
        }
        return true;
    }

    HttpRequest parseRequest(const std::string& raw) {
        HttpRequest req;
        std::istringstream ss(raw); std::string line;
        std::getline(ss,line); if(!line.empty()&&line.back()=='\r')line.pop_back();
        std::istringstream rl(line); std::string fullPath;
        rl>>req.method>>fullPath;
        auto qp=fullPath.find('?');
        if(qp!=std::string::npos){req.path=fullPath.substr(0,qp);req.query=fullPath.substr(qp+1);}
        else req.path=fullPath;
        while(std::getline(ss,line)){
            if(!line.empty()&&line.back()=='\r')line.pop_back();
            if(line.empty())break;
            auto colon=line.find(':');
            if(colon!=std::string::npos){
                auto key=line.substr(0,colon); auto val=line.substr(colon+2);
                std::transform(key.begin(),key.end(),key.begin(),::tolower);
                req.headers[key]=val;
            }
        }
        int len=0;
        if(req.headers.count("content-length"))try{len=std::stoi(req.headers["content-length"]);}catch(...){}
        if(len>0){req.body.resize(len);ss.read(&req.body[0],len);}
        return req;
    }

    void handleClient(int clientFd) {
        std::string raw; char buf[8192];
        while(true){
            int n=recv(clientFd,buf,sizeof(buf)-1,0);
            if(n<=0)break; buf[n]=0; raw+=buf;
            if(raw.find("\r\n\r\n")!=std::string::npos){
                auto cl=raw.find("content-length: ");
                if(cl==std::string::npos)cl=raw.find("Content-Length: ");
                if(cl!=std::string::npos){
                    auto end=raw.find("\r\n",cl);
                    int bodyLen=0; try{bodyLen=std::stoi(raw.substr(cl+16,end-(cl+16)));}catch(...){}
                    size_t bs=raw.find("\r\n\r\n")+4;
                    if((int)(raw.size()-bs)>=bodyLen)break;
                }else break;
            }
        }
        HttpRequest req=parseRequest(raw);
        HttpResponse resp;

        if(req.method=="OPTIONS"){resp.status=204;resp.statusText="No Content";}
        else if(req.path=="/"||req.path=="/index.html"){resp.html(staticHtml);}
        else {
            bool found=false;
            for(auto&r:routes){
                std::unordered_map<std::string,std::string> params;
                if(matchRoute(r,req.method,req.path,params)){
                    req.params=params;
                    try{r.handler(req,resp);}catch(std::exception&e){resp.err(500,e.what());}
                    found=true;break;
                }
            }
            if(!found)resp.err(404,"Not Found");
        }
        std::string out=resp.build();
        send(clientFd,out.c_str(),out.size(),MSG_NOSIGNAL);
        close(clientFd);
    }

public:
    void addRoute(const std::string& m, const std::string& pat, std::function<void(const HttpRequest&,HttpResponse&)> h){
        routes.push_back({m,pat,h});
    }
    void setHtml(const std::string& html){staticHtml=html;}
    void addSseRoute(const std::string& path, std::function<void(int,const HttpRequest&)> onConnect){
        // Handled specially below
        sseRoutes[path]=onConnect;
    }
    std::map<std::string,std::function<void(int,const HttpRequest&)>> sseRoutes;

    bool listen(int port){
        serverFd=socket(AF_INET,SOCK_STREAM,0);
        if(serverFd<0)return false;
        int opt=1; setsockopt(serverFd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
        sockaddr_in addr{}; addr.sin_family=AF_INET;
        addr.sin_addr.s_addr=INADDR_ANY; addr.sin_port=htons(port);
        if(bind(serverFd,(sockaddr*)&addr,sizeof(addr))<0)return false;
        if(::listen(serverFd,128)<0)return false;
        running=true;
        while(running){
            sockaddr_in ca{}; socklen_t cl=sizeof(ca);
            int cfd=accept(serverFd,(sockaddr*)&ca,&cl);
            if(cfd<0)continue;

            // Read request then route (SSE or normal)
            std::thread([this,cfd]{
                std::string raw; char buf[8192];
                while(true){
                    int n=recv(cfd,buf,sizeof(buf)-1,0);
                    if(n<=0)break; buf[n]=0; raw+=buf;
                    if(raw.find("\r\n\r\n")!=std::string::npos){
                        auto cl=raw.find("content-length: ");
                        if(cl==std::string::npos)cl=raw.find("Content-Length: ");
                        if(cl!=std::string::npos){
                            auto end=raw.find("\r\n",cl);
                            int bl=0;try{bl=std::stoi(raw.substr(cl+16,end-(cl+16)));}catch(...){}
                            size_t bs=raw.find("\r\n\r\n")+4;
                            if((int)(raw.size()-bs)>=bl)break;
                        }else break;
                    }
                }
                HttpRequest req=parseRequest(raw);
                // Check SSE routes
                bool handled=false;
                for(auto&sr:sseRoutes){
                    if(req.path==sr.first && req.method=="GET"){
                        sr.second(cfd,req); handled=true; break;
                    }
                }
                if(!handled){
                    HttpResponse resp;
                    if(req.method=="OPTIONS"){resp.status=204;resp.statusText="No Content";}
                    else if(req.path=="/"||req.path=="/index.html"){resp.html(staticHtml);}
                    else {
                        bool found=false;
                        for(auto&r:routes){
                            std::unordered_map<std::string,std::string> params;
                            if(matchRoute(r,req.method,req.path,params)){
                                req.params=params;
                                try{r.handler(req,resp);}catch(std::exception&e){resp.err(500,e.what());}catch(...){resp.err(500,"Unknown error");}
                                found=true;break;
                            }
                        }
                        if(!found)resp.err(404,"Not Found");
                    }
                    std::string out=resp.build();
                    send(cfd,out.c_str(),out.size(),MSG_NOSIGNAL);
                    close(cfd);
                }
            }).detach();
        }
        close(serverFd); return true;
    }
    void stop(){running=false;close(serverFd);}
};

// ═══════════════════════════════════════════════════════════════════
//  JSON helpers
// ═══════════════════════════════════════════════════════════════════
static std::string escJ(const std::string& s){
    std::string out;
    for(char c:s){if(c=='"')out+="\\\"";else if(c=='\\')out+="\\\\";else if(c=='\n')out+="\\n";else out+=c;}
    return out;
}
static Json userToJson(const User& u){
    Json j=Json::object();
    j["id"]=Json(u.id);j["name"]=Json(u.name);j["room"]=Json(u.room);
    j["username"]=Json(u.username);j["role"]=Json(u.role);j["createdAt"]=Json(u.createdAt);
    return j;
}
static Json noticeToJson(const Notice& n){
    Json j=Json::object();j["id"]=Json(n.id);j["text"]=Json(n.text);j["active"]=Json(n.active);j["urgent"]=Json(n.urgent);return j;
}
static Json newsToJson(const NewsItem& it){
    Json j=Json::object();j["id"]=Json(it.id);j["title"]=Json(it.title);j["date"]=Json(it.date);j["category"]=Json(it.category);j["content"]=Json(it.content);return j;
}
static Json eventToJson(const Event& e){
    Json j=Json::object();
    j["id"]=Json(e.id);j["name"]=Json(e.name);j["date"]=Json(e.date);j["time"]=Json(e.time_);
    j["description"]=Json(e.description);j["location"]=Json(e.location);
    j["maxParticipants"]=Json((long long)e.maxParticipants);j["createdAt"]=Json(e.createdAt);
    Json jp=Json::array();for(auto&p:e.participants)jp.push(Json(p));j["participants"]=jp;
    return j;
}
static Json laundryToJson(const LaundryBooking& b){
    Json j=Json::object();j["id"]=Json(b.id);j["name"]=Json(b.name);j["room"]=Json(b.room);
    j["userId"]=Json(b.userId);j["machineId"]=Json(b.machineId);j["date"]=Json(b.date);j["slot"]=Json(b.slot);j["createdAt"]=Json(b.createdAt);return j;
}
static Json equipToJson(const EquipmentBooking& b){
    Json j=Json::object();j["id"]=Json(b.id);j["name"]=Json(b.name);j["room"]=Json(b.room);
    j["userId"]=Json(b.userId);j["item"]=Json(b.item);j["date"]=Json(b.date);j["duration"]=Json((long long)b.duration);j["createdAt"]=Json(b.createdAt);return j;
}

static std::string getToken(const HttpRequest& req){
    auto it=req.headers.find("authorization");
    if(it!=req.headers.end()&&it->second.substr(0,7)=="Bearer ")return it->second.substr(7);
    return "";
}

// ═══════════════════════════════════════════════════════════════════
//  Route registration
// ═══════════════════════════════════════════════════════════════════
void registerRoutes(HttpServer& srv, Database& db, SessionStore& sessions, SSEBroker& sse) {

    // ── AUTH ──────────────────────────────────────────────────────

    // POST /api/auth/register
    srv.addRoute("POST","/api/auth/register",[&](const HttpRequest& req, HttpResponse& res){
        Json body=parseJson(req.body);
        std::string name=body["name"].asString(), room=body["room"].asString();
        std::string uname=body["username"].asString(), pw=body["password"].asString();
        if(name.empty()||room.empty()||uname.empty()||pw.empty()){res.err(400,"Name, room number, username, and password are all required.");return;}
        if(pw.size()<6){res.err(400,"Password must be at least 6 characters.");return;}
        // Validate uniqueness (quick check, then hash outside lock)
        {
            std::lock_guard<std::mutex> lk(db.mtx);
            if(db.findUserByUsername(uname)){res.err(409,"That username is already taken.");return;}
            if(db.findUserByRoom(room)){res.err(409,"A resident is already registered for that room number.");return;}
        }
        // Do slow hashing OUTSIDE the lock
        std::string salt=randomHex(16);
        std::string hash=hashPassword(pw,salt);
        // Re-acquire to insert
        std::lock_guard<std::mutex> lk(db.mtx);
        // Re-check (TOCTOU guard)
        if(db.findUserByUsername(uname)){res.err(409,"That username is already taken.");return;}
        if(db.findUserByRoom(room)){res.err(409,"A resident is already registered for that room number.");return;}
        User u; u.id=makeUID(); u.name=name; u.room=room; u.username=uname;
        u.salt=salt; u.hash=hash; u.role="resident"; u.createdAt=nowISO();
        db.users.push_back(u); db.save();
        std::string token=sessions.create(u.id);
        Json resp=Json::object(); resp["token"]=Json(token); resp["user"]=userToJson(u);
        res.json(resp.dump());
    });

    // POST /api/auth/login
    srv.addRoute("POST","/api/auth/login",[&](const HttpRequest& req, HttpResponse& res){
        Json body=parseJson(req.body);
        std::string uname=body["username"].asString(), pw=body["password"].asString();
        if(uname.empty()||pw.empty()){res.err(400,"Username and password required.");return;}
        // Get salt without holding lock long
        std::string salt, storedHash, userId;
        {
            std::lock_guard<std::mutex> lk(db.mtx);
            User* u=db.findUserByUsername(uname);
            if(!u){res.err(401,"Incorrect username or password.");return;}
            salt=u->salt; storedHash=u->hash; userId=u->id;
        }
        // Do slow hashing OUTSIDE the lock
        std::string computed=hashPassword(pw,salt);
        if(computed!=storedHash){res.err(401,"Incorrect username or password.");return;}
        // Re-acquire to create session and build response
        std::lock_guard<std::mutex> lk(db.mtx);
        User* u=db.findUser(userId);
        if(!u){res.err(401,"Incorrect username or password.");return;}
        std::string token=sessions.create(u->id);
        Json resp=Json::object(); resp["token"]=Json(token); resp["user"]=userToJson(*u);
        res.json(resp.dump());
    });

    // POST /api/auth/logout
    srv.addRoute("POST","/api/auth/logout",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        sessions.remove(getToken(req));
        res.json("{\"success\":true}");
    });

    // GET /api/auth/me
    srv.addRoute("GET","/api/auth/me",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string uid=sessions.getUserId(getToken(req));
        User* u=db.findUser(uid);
        if(!u){res.err(401,"Not logged in.");return;}
        res.json(userToJson(*u).dump());
    });




    // ── SSE ───────────────────────────────────────────────────────
    srv.addSseRoute("/api/stream",[&](int fd, const HttpRequest& req){
        std::string uid=sessions.getUserId(getToken(req));
        if(db.findUser(uid)==nullptr){
            std::string r="HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
            send(fd,r.c_str(),r.size(),MSG_NOSIGNAL); close(fd); return;
        }
        std::string header="HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nConnection: keep-alive\r\n\r\n: connected\n\n";
        send(fd,header.c_str(),header.size(),MSG_NOSIGNAL);
        sse.add(fd);
        // Thread keeps the connection alive; client disconnect is detected on next broadcast
    });

    // ── USERS (admin) ─────────────────────────────────────────────
    srv.addRoute("GET","/api/users",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        Json arr=Json::array(); for(auto&u:db.users)arr.push(userToJson(u));
        res.json(arr.dump());
    });
    srv.addRoute("DELETE","/api/users/:id",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        std::string id=req.params.at("id");
        if(id==me->id){res.err(400,"Cannot delete your own account.");return;}
        db.users.erase(std::remove_if(db.users.begin(),db.users.end(),[&](const User&u){return u.id==id;}),db.users.end());
        db.save(); res.json("{\"success\":true}");
    });

    // ── NOTICES ───────────────────────────────────────────────────
    srv.addRoute("GET","/api/notices",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        { std::string _uid=sessions.getUserId(getToken(req)); if(!db.findUser(_uid)){res.err(401,"Please log in.");return;}}
        Json arr=Json::array(); for(auto&n:db.notices)if(n.active)arr.push(noticeToJson(n));
        res.json(arr.dump());
    });
    srv.addRoute("POST","/api/notices",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        Json body=parseJson(req.body);
        Notice n; n.id=makeUID(); n.text=body["text"].asString(); n.active=true; n.urgent=body["urgent"].asBool();
        db.notices.push_back(n); db.save();
        Json active=Json::array(); for(auto&x:db.notices)if(x.active)active.push(noticeToJson(x));
        sse.broadcast("notices",active.dump());
        res.json(noticeToJson(n).dump());
    });
    srv.addRoute("DELETE","/api/notices/:id",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        std::string id=req.params.at("id");
        for(auto&n:db.notices)if(n.id==id)n.active=false;
        db.save();
        Json active=Json::array(); for(auto&x:db.notices)if(x.active)active.push(noticeToJson(x));
        sse.broadcast("notices",active.dump());
        res.json("{\"success\":true}");
    });

    // ── NEWS ──────────────────────────────────────────────────────
    srv.addRoute("GET","/api/news",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        { std::string _uid=sessions.getUserId(getToken(req)); if(!db.findUser(_uid)){res.err(401,"Please log in.");return;}}
        auto list=db.news;
        std::sort(list.begin(),list.end(),[](auto&a,auto&b){return b.date<a.date;});
        Json arr=Json::array(); for(auto&it:list)arr.push(newsToJson(it));
        res.json(arr.dump());
    });
    srv.addRoute("POST","/api/news",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        Json body=parseJson(req.body);
        NewsItem it; it.id=makeUID(); it.title=body["title"].asString();
        it.date=body["date"].asString().empty()?todayStr():body["date"].asString();
        it.category=body["category"].asString().empty()?"General":body["category"].asString();
        it.content=body["content"].asString();
        if(it.title.empty()||it.content.empty()){res.err(400,"Title and content required.");return;}
        db.news.insert(db.news.begin(),it); db.save();
        sse.broadcast("news",newsToJson(it).dump());
        res.json(newsToJson(it).dump());
    });
    srv.addRoute("DELETE","/api/news/:id",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        std::string id=req.params.at("id");
        db.news.erase(std::remove_if(db.news.begin(),db.news.end(),[&](const NewsItem&x){return x.id==id;}),db.news.end());
        db.save(); sse.broadcast("news-deleted","{\"id\":\""+id+"\"}");
        res.json("{\"success\":true}");
    });

    // ── EVENTS ────────────────────────────────────────────────────
    srv.addRoute("GET","/api/events",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        { std::string _uid=sessions.getUserId(getToken(req)); if(!db.findUser(_uid)){res.err(401,"Please log in.");return;}}
        auto list=db.events;
        std::sort(list.begin(),list.end(),[](auto&a,auto&b){return a.date<b.date;});
        Json arr=Json::array(); for(auto&e:list)arr.push(eventToJson(e));
        res.json(arr.dump());
    });
    srv.addRoute("POST","/api/events",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        Json body=parseJson(req.body);
        Event e; e.id=makeUID(); e.name=body["name"].asString(); e.date=body["date"].asString();
        e.time_=body["time"].asString().empty()?"00:00":body["time"].asString();
        e.description=body["description"].asString(); e.location=body["location"].asString().empty()?"TBD":body["location"].asString();
        e.maxParticipants=body["maxParticipants"].asLong()?body["maxParticipants"].asLong():20;
        e.createdAt=todayStr();
        if(e.name.empty()||e.date.empty()){res.err(400,"Name and date required.");return;}
        db.events.push_back(e); db.save();
        Json arr=Json::array();for(auto&ev:db.events)arr.push(eventToJson(ev));
        sse.broadcast("events",arr.dump()); res.json(eventToJson(e).dump());
    });
    srv.addRoute("DELETE","/api/events/:id",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        if(me->role!="admin"){res.err(403,"Admin only.");return;}
        std::string id=req.params.at("id");
        db.events.erase(std::remove_if(db.events.begin(),db.events.end(),[&](const Event&e){return e.id==id;}),db.events.end());
        db.save();
        Json arr=Json::array();for(auto&ev:db.events)arr.push(eventToJson(ev));
        sse.broadcast("events",arr.dump()); res.json("{\"success\":true}");
    });
    // POST /api/events/:id/register
    srv.addRoute("POST","/api/events/:id/register",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        std::string id=req.params.at("id");
        Event* e=db.findEvent(id);
        if(!e){res.err(404,"Event not found.");return;}
        Json body=parseJson(req.body);
        std::string label=me->name+" (Room "+me->room+")";
        if(body["cancel"].asBool()){
            e->participants.erase(std::remove(e->participants.begin(),e->participants.end(),label),e->participants.end());
        } else {
            if((int)e->participants.size()>=e->maxParticipants){res.err(400,"This event is full.");return;}
            if(std::find(e->participants.begin(),e->participants.end(),label)==e->participants.end())
                e->participants.push_back(label);
        }
        db.save();
        Json arr=Json::array();for(auto&ev:db.events)arr.push(eventToJson(ev));
        sse.broadcast("events",arr.dump()); res.json(eventToJson(*e).dump());
    });

    // ── LAUNDRY ───────────────────────────────────────────────────
    srv.addRoute("GET","/api/laundry",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        { std::string _uid=sessions.getUserId(getToken(req)); if(!db.findUser(_uid)){res.err(401,"Please log in.");return;}}
        Json arr=Json::array(); for(auto&b:db.laundry)arr.push(laundryToJson(b));
        res.json(arr.dump());
    });
    srv.addRoute("POST","/api/laundry",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        Json body=parseJson(req.body);
        std::string mid=body["machineId"].asString(), date=body["date"].asString(), slot=body["slot"].asString();
        if(mid.empty()||date.empty()||slot.empty()){res.err(400,"Machine, date, and time slot required.");return;}
        for(auto&b:db.laundry)if(b.machineId==mid&&b.date==date&&b.slot==slot){res.err(409,"That slot is already booked.");return;}
        LaundryBooking bk; bk.id=makeUID(); bk.name=me->name; bk.room=me->room;
        bk.userId=me->id; bk.machineId=mid; bk.date=date; bk.slot=slot; bk.createdAt=nowISO();
        db.laundry.push_back(bk); db.save();
        Json arr=Json::array();for(auto&b:db.laundry)arr.push(laundryToJson(b));
        sse.broadcast("laundry",arr.dump()); res.json(laundryToJson(bk).dump());
    });
    srv.addRoute("DELETE","/api/laundry/:id",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        std::string id=req.params.at("id");
        LaundryBooking* bk=db.findLaundry(id);
        if(!bk){res.err(404,"Not found.");return;}
        if(me->role!="admin"&&bk->userId!=me->id){res.err(403,"You can only cancel your own bookings.");return;}
        db.laundry.erase(std::remove_if(db.laundry.begin(),db.laundry.end(),[&](const LaundryBooking&b){return b.id==id;}),db.laundry.end());
        db.save();
        Json arr=Json::array();for(auto&b:db.laundry)arr.push(laundryToJson(b));
        sse.broadcast("laundry",arr.dump()); res.json("{\"success\":true}");
    });

    // ── EQUIPMENT ─────────────────────────────────────────────────
    srv.addRoute("GET","/api/equipment",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        { std::string _uid=sessions.getUserId(getToken(req)); if(!db.findUser(_uid)){res.err(401,"Please log in.");return;}}
        Json arr=Json::array(); for(auto&b:db.equipment)arr.push(equipToJson(b));
        res.json(arr.dump());
    });
    srv.addRoute("POST","/api/equipment",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        Json body=parseJson(req.body);
        std::string item=body["item"].asString(), date=body["date"].asString();
        if(item.empty()||date.empty()){res.err(400,"Item and date required.");return;}
        for(auto&b:db.equipment)if(b.userId==me->id&&b.item==item&&b.date==date){res.err(409,"You already have a booking for this item today.");return;}
        EquipmentBooking bk; bk.id=makeUID(); bk.name=me->name; bk.room=me->room;
        bk.userId=me->id; bk.item=item; bk.date=date; bk.duration=60; bk.createdAt=nowISO();
        db.equipment.push_back(bk); db.save();
        Json arr=Json::array();for(auto&b:db.equipment)arr.push(equipToJson(b));
        sse.broadcast("equipment",arr.dump()); res.json(equipToJson(bk).dump());
    });
    srv.addRoute("DELETE","/api/equipment/:id",[&](const HttpRequest& req, HttpResponse& res){
        std::lock_guard<std::mutex> lk(db.mtx);
        std::string _uid=sessions.getUserId(getToken(req)); User* me=db.findUser(_uid); if(!me){res.err(401,"Please log in.");return;}
        std::string id=req.params.at("id");
        EquipmentBooking* bk=db.findEquipment(id);
        if(!bk){res.err(404,"Not found.");return;}
        if(me->role!="admin"&&bk->userId!=me->id){res.err(403,"You can only cancel your own bookings.");return;}
        db.equipment.erase(std::remove_if(db.equipment.begin(),db.equipment.end(),[&](const EquipmentBooking&b){return b.id==id;}),db.equipment.end());
        db.save();
        Json arr=Json::array();for(auto&b:db.equipment)arr.push(equipToJson(b));
        sse.broadcast("equipment",arr.dump()); res.json("{\"success\":true}");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  Embedded Frontend HTML
// ═══════════════════════════════════════════════════════════════════
static std::string buildFrontend();  // defined after main

// ═══════════════════════════════════════════════════════════════════
//  main
// ═══════════════════════════════════════════════════════════════════
int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);

    int port = 3000;
    std::string dbPath = "residence_db.json";
    if (argc > 1) port = std::atoi(argv[1]);
    if (argc > 2) dbPath = argv[2];

    Database db;
    SessionStore sessions;
    SSEBroker sse;

    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║   Residence Management System            ║\n";
    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "  Loading: " << dbPath << "\n";
    db.load(dbPath);

    HttpServer srv;
    registerRoutes(srv, db, sessions, sse);
    srv.setHtml(buildFrontend());

    std::cout << "╠══════════════════════════════════════════╣\n";
    std::cout << "║  Local:   http://localhost:" << port << "           ║\n";
    std::cout << "║  Network: http://<your-ip>:" << port << "          ║\n";
    std::cout << "║  Admin:   username=admin  pw=admin123    ║\n";
    std::cout << "║  Press Ctrl+C to stop                    ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n\n";

    srv.listen(port);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════
//  Frontend — complete SPA with auth, all pages
// ═══════════════════════════════════════════════════════════════════
static std::string buildFrontend() {
return R"HTMLEOF(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Residence Portal</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,500;0,700;1,500&family=DM+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --cream:#f5f0e8;--cream2:#ede7d9;--cream3:#e4dccb;--parchment:#faf7f2;
  --slate:#2c3341;--slate2:#3d4758;--slate3:#515d72;
  --amber:#c9803a;--amber2:#e09550;--amber3:#f5b06a;
  --green:#4a7c59;--green2:#5d9970;
  --red:#b85450;--red2:#d96b67;
  --text:#2c3341;--muted:#7a8494;--border:#ddd5c4;
  --shadow:rgba(44,51,65,.10);--shadow2:rgba(44,51,65,.18);
  --serif:'Playfair Display',Georgia,serif;
  --sans:'DM Sans',system-ui,sans-serif;
  --r:10px;--r2:16px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{background:var(--cream);color:var(--text);font-family:var(--sans);font-size:15px;line-height:1.6;min-height:100vh}

/* AUTH */
#auth-screen{position:fixed;inset:0;z-index:1000;background:linear-gradient(135deg,var(--slate) 0%,var(--slate2) 60%,#1e2530 100%);display:flex;align-items:center;justify-content:center;padding:20px}
.auth-card{background:var(--parchment);border:1px solid var(--border);border-radius:20px;padding:40px;width:100%;max-width:460px;box-shadow:0 32px 80px rgba(0,0,0,.35);animation:authIn .4s cubic-bezier(.16,1,.3,1)}
@keyframes authIn{from{opacity:0;transform:translateY(24px) scale(.97)}to{opacity:1;transform:none}}
.auth-logo{display:flex;align-items:center;gap:12px;margin-bottom:28px}
.auth-logo-icon{width:46px;height:46px;background:var(--amber);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px}
.auth-logo-name{font-family:var(--serif);font-size:22px;font-weight:700;color:var(--slate);line-height:1.1}
.auth-logo-sub{font-size:12px;color:var(--muted)}
.auth-tabs{display:flex;background:var(--cream2);border-radius:var(--r);padding:4px;gap:4px;margin-bottom:24px}
.auth-tab{flex:1;padding:8px;border:none;border-radius:8px;background:none;font-family:var(--sans);font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;transition:all .2s}
.auth-tab.active{background:#fff;color:var(--slate);box-shadow:0 1px 4px var(--shadow)}
.auth-form{display:none}
.auth-form.active{display:block}
.auth-form-title{font-family:var(--serif);font-size:22px;color:var(--slate);margin-bottom:4px}
.auth-form-sub{font-size:13px;color:var(--muted);margin-bottom:20px}
.auth-err{background:rgba(185,84,80,.1);border:1px solid rgba(185,84,80,.3);border-radius:var(--r);padding:10px 14px;font-size:13px;color:var(--red);margin-bottom:14px;display:none}
.auth-err.show{display:block}

/* FORMS */
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:11px;font-weight:600;color:var(--slate2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px}
.form-group input,.form-group select,.form-group textarea{width:100%;background:#fff;border:1.5px solid var(--border);border-radius:var(--r);padding:10px 13px;font-family:var(--sans);font-size:14px;color:var(--text);outline:none;transition:border .18s,box-shadow .18s}
.form-group input:focus,.form-group select:focus,.form-group textarea:focus{border-color:var(--amber);box-shadow:0 0 0 3px rgba(201,128,58,.12)}
.form-group input::placeholder{color:var(--muted)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.form-group textarea{min-height:80px;resize:vertical}

/* TOPBAR */
#topbar{background:var(--slate);color:#fff;padding:0 24px;display:flex;align-items:center;height:58px;position:sticky;top:0;z-index:100;box-shadow:0 2px 16px var(--shadow2)}
.brand{font-family:var(--serif);font-size:19px;font-weight:700;color:var(--amber3);margin-right:20px;display:flex;align-items:center;gap:10px;cursor:pointer;flex-shrink:0}
.brand-icon{width:32px;height:32px;background:var(--amber);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px}
#nav{display:flex;gap:2px;flex:1;overflow-x:auto;scrollbar-width:none}
#nav::-webkit-scrollbar{display:none}
.nav-btn{background:none;border:none;color:rgba(255,255,255,.6);font-family:var(--sans);font-size:13px;font-weight:500;padding:6px 14px;border-radius:6px;cursor:pointer;white-space:nowrap;transition:all .2s}
.nav-btn:hover{color:#fff;background:rgba(255,255,255,.08)}
.nav-btn.active{color:var(--amber3);background:rgba(201,128,58,.15)}
#user-area{margin-left:auto;display:flex;align-items:center;gap:10px;flex-shrink:0}
.user-chip{display:flex;align-items:center;gap:8px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.15);border-radius:20px;padding:4px 14px 4px 6px}
.user-av{width:26px;height:26px;background:var(--amber);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0}
.user-info{line-height:1.2}
.user-name{color:#fff;font-size:12px;font-weight:600}
.user-room{color:rgba(255,255,255,.5);font-size:10px}
.logout-btn{background:none;border:1px solid rgba(255,255,255,.2);border-radius:6px;color:rgba(255,255,255,.55);font-family:var(--sans);font-size:11px;font-weight:600;padding:5px 10px;cursor:pointer;transition:all .2s}
.logout-btn:hover{background:rgba(255,255,255,.1);color:#fff}

/* NOTICE BANNER */
#notice-banner{background:linear-gradient(135deg,var(--amber) 0%,var(--amber2) 100%);color:#fff;display:none}
#notice-banner.show{display:block}
.notice-inner{max-width:1100px;margin:0 auto;padding:10px 24px;display:flex;gap:10px}
.notice-icon{font-size:15px;margin-top:2px;flex-shrink:0}
.n-item{font-size:13px;font-weight:500}
.n-item+.n-item{margin-top:4px;padding-top:4px;border-top:1px solid rgba(255,255,255,.25)}
.n-urgent{font-weight:700}

/* MAIN */
main{max-width:1100px;margin:0 auto;padding:32px 24px 64px;width:100%}
.page{display:none;animation:fadeIn .3s ease}
.page.active{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
.page-title{font-family:var(--serif);font-size:32px;font-weight:700;color:var(--slate);margin-bottom:6px;letter-spacing:-.5px}
.page-sub{color:var(--muted);font-size:14px;margin-bottom:28px}
.sec-title{font-family:var(--serif);font-size:20px;font-weight:500;color:var(--slate);margin-bottom:16px;display:flex;align-items:center;gap:10px}
.sec-title::after{content:'';flex:1;height:1px;background:var(--border)}

/* CARDS */
.card{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:20px 22px;box-shadow:0 2px 8px var(--shadow);transition:box-shadow .2s,transform .2s}
.card:hover{box-shadow:0 6px 20px var(--shadow2);transform:translateY(-2px)}
.grid{display:grid;gap:16px}
.grid-2{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}

/* BADGES */
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.3px;text-transform:uppercase}
.b-kitchen{background:rgba(74,124,89,.15);color:var(--green)}
.b-laundry{background:rgba(100,140,200,.15);color:#4a6fa5}
.b-maintenance{background:rgba(185,84,80,.12);color:var(--red)}
.b-general{background:rgba(201,128,58,.15);color:var(--amber)}
.b-upcoming{background:rgba(74,124,89,.15);color:var(--green)}
.b-past{background:rgba(120,130,148,.15);color:var(--muted)}
.b-full{background:rgba(185,84,80,.12);color:var(--red)}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 18px;border:none;border-radius:var(--r);font-family:var(--sans);font-size:13px;font-weight:600;cursor:pointer;transition:all .18s;white-space:nowrap;text-decoration:none}
.btn-p{background:var(--amber);color:#fff}.btn-p:hover{background:var(--amber2);transform:translateY(-1px);box-shadow:0 4px 12px rgba(201,128,58,.35)}
.btn-s{background:var(--slate);color:#fff}.btn-s:hover{background:var(--slate2);transform:translateY(-1px)}
.btn-g{background:var(--green);color:#fff}.btn-g:hover{background:var(--green2)}
.btn-r{background:var(--red);color:#fff}.btn-r:hover{background:var(--red2)}
.btn-gh{background:transparent;color:var(--slate);border:1.5px solid var(--border)}.btn-gh:hover{border-color:var(--amber);color:var(--amber)}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-full{width:100%;justify-content:center}

/* TOOLBAR */
.toolbar{display:flex;gap:10px;align-items:center;margin-bottom:22px;flex-wrap:wrap}
.toolbar input,.toolbar select{background:#fff;border:1.5px solid var(--border);border-radius:var(--r);padding:8px 13px;font-family:var(--sans);font-size:13px;color:var(--text);outline:none;transition:border .18s}
.toolbar input:focus,.toolbar select:focus{border-color:var(--amber)}
.toolbar input{flex:1;min-width:180px}
.toolbar input::placeholder{color:var(--muted)}

/* DASHBOARD */
.dash-hero{background:linear-gradient(135deg,var(--slate) 0%,var(--slate2) 100%);color:#fff;border-radius:var(--r2);padding:36px;margin-bottom:28px;position:relative;overflow:hidden}
.dash-hero::before{content:'';position:absolute;top:-40px;right:-40px;width:220px;height:220px;background:radial-gradient(circle,rgba(201,128,58,.25) 0%,transparent 70%);border-radius:50%}
.dash-hero-title{font-family:var(--serif);font-size:32px;font-weight:700;margin-bottom:6px;position:relative}
.dash-hero-sub{color:rgba(255,255,255,.65);font-size:15px;position:relative}
.dash-hero-date{position:absolute;top:28px;right:32px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.2);padding:8px 16px;border-radius:var(--r);font-size:13px;color:rgba(255,255,255,.8)}
.stats-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin-bottom:28px}
.stat-card{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:18px 20px;box-shadow:0 2px 8px var(--shadow)}
.stat-lbl{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:var(--muted)}
.stat-val{font-family:var(--serif);font-size:28px;font-weight:700;color:var(--slate);margin-top:2px}
.dash-grid{display:grid;grid-template-columns:1fr 370px;gap:24px}
@media(max-width:820px){.dash-grid{grid-template-columns:1fr}}

/* NEWS CARDS */
.news-card{border-left:3px solid var(--amber)}
.nc-meta{display:flex;align-items:center;gap:10px;margin-bottom:8px}
.nc-title{font-family:var(--serif);font-size:17px;font-weight:500;color:var(--slate);margin-bottom:6px;line-height:1.35}
.nc-body{font-size:14px;color:var(--slate2);line-height:1.65}
.nc-date{font-size:12px;color:var(--muted)}

/* EVENT CARDS */
.event-card{border-top:3px solid var(--amber)}
.event-card.past{border-top-color:var(--border);opacity:.75}
.evt-name{font-family:var(--serif);font-size:18px;font-weight:500;color:var(--slate);margin-bottom:6px}
.evt-meta{display:flex;flex-wrap:wrap;gap:10px;font-size:13px;color:var(--muted)}
.evt-desc{font-size:14px;color:var(--slate2);margin:10px 0 14px;line-height:1.6}
.evt-footer{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.cap-bar{width:120px;height:5px;background:var(--cream3);border-radius:3px;display:inline-block;margin-left:8px;vertical-align:middle;overflow:hidden}
.cap-fill{height:100%;border-radius:3px;background:var(--green);transition:width .4s}
.cap-fill.full{background:var(--red)}
.reg-section{margin-top:14px;border-top:1px solid var(--border);padding-top:14px;display:none}
.reg-section.open{display:block}

/* TABLE */
.tbl-wrap{overflow-x:auto;margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:14px}
thead th{background:var(--slate);color:rgba(255,255,255,.8);padding:10px 14px;text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;white-space:nowrap}
thead th:first-child{border-radius:8px 0 0 0}thead th:last-child{border-radius:0 8px 0 0}
tbody tr{border-bottom:1px solid var(--border);transition:background .12s}
tbody tr:hover{background:var(--cream2)}
tbody td{padding:10px 14px;color:var(--slate2)}
tbody td:first-child{color:var(--slate);font-weight:500}
.tbl-empty{text-align:center;color:var(--muted);padding:32px!important;font-style:italic}

/* SLOT GRID */
.slot-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px;margin-top:10px}
.slot{padding:9px 12px;border-radius:var(--r);font-size:13px;font-weight:500;text-align:center;cursor:pointer;transition:all .15s;border:1.5px solid var(--border);background:#fff;color:var(--slate)}
.slot:hover{border-color:var(--amber);color:var(--amber)}
.slot.taken{background:var(--cream3);color:var(--muted);cursor:not-allowed;border-style:dashed}
.slot.selected{background:var(--amber);color:#fff;border-color:var(--amber)}

/* ADMIN */
.adm-sec{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:24px;margin-bottom:20px;box-shadow:0 2px 8px var(--shadow)}
.adm-sec h3{font-family:var(--serif);font-size:18px;color:var(--slate);margin-bottom:16px;padding-bottom:10px;border-bottom:1px solid var(--border)}
.adm-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--cream3);gap:12px;flex-wrap:wrap}
.adm-row:last-child{border-bottom:none}
.adm-info strong{font-size:14px;font-weight:600;color:var(--slate)}
.adm-info small{display:block;font-size:12px;color:var(--muted)}

/* MACHINE TABS */
.machine-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.m-tab{padding:6px 16px;border:1.5px solid var(--border);border-radius:20px;background:#fff;font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;color:var(--text)}
.m-tab.active{background:var(--slate);color:#fff;border-color:var(--slate)}

/* PILL */
.pill{display:inline-flex;align-items:center;gap:5px;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:500}
.pill-a{background:rgba(201,128,58,.15);color:var(--amber)}
.pill-s{background:rgba(44,51,65,.1);color:var(--slate)}

/* MODAL */
.overlay{position:fixed;inset:0;background:rgba(44,51,65,.55);backdrop-filter:blur(4px);z-index:500;display:none;align-items:center;justify-content:center;padding:20px}
.overlay.open{display:flex}
.modal{background:var(--parchment);border:1px solid var(--border);border-radius:var(--r2);padding:28px;width:100%;max-width:520px;max-height:90vh;overflow-y:auto;box-shadow:0 20px 60px rgba(44,51,65,.25);animation:mIn .22s ease;position:relative}
@keyframes mIn{from{opacity:0;transform:scale(.96) translateY(-10px)}to{opacity:1;transform:none}}
.modal h2{font-family:var(--serif);font-size:22px;font-weight:700;color:var(--slate);margin-bottom:6px}
.modal-sub{font-size:14px;color:var(--muted);margin-bottom:20px}
.m-close{position:absolute;top:14px;right:16px;background:none;border:none;font-size:22px;color:var(--muted);cursor:pointer;padding:4px;line-height:1}
.m-close:hover{color:var(--text)}
.m-acts{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}

/* TOAST */
#toasts{position:fixed;bottom:22px;right:22px;z-index:999;display:flex;flex-direction:column;gap:8px}
.toast{background:var(--slate);color:#fff;border-radius:var(--r);padding:12px 18px;font-size:13px;box-shadow:0 8px 24px rgba(44,51,65,.3);animation:tIn .28s ease;max-width:300px;display:flex;align-items:center;gap:10px;border-left:3px solid var(--amber)}
.toast.ok{border-left-color:var(--green)}.toast.er{border-left-color:var(--red)}
@keyframes tIn{from{opacity:0;transform:translateX(16px)}to{opacity:1;transform:none}}
.divider{height:1px;background:var(--border);margin:24px 0}
.empty{text-align:center;padding:44px 24px;color:var(--muted);font-size:14px}
.empty-icon{font-size:38px;display:block;margin-bottom:10px;opacity:.4}

/* MACHINES */
.machine-tabs,.slot-grid{margin-bottom:8px}
</style>
</head>
<body>

<!-- AUTH SCREEN -->
<div id="auth-screen">
  <div class="auth-card">
    <div class="auth-logo">
      <div class="auth-logo-icon">🏠</div>
      <div>
        <div class="auth-logo-name">Residence Portal</div>
        <div class="auth-logo-sub">Shared Living Management System</div>
      </div>
    </div>
    <div class="auth-tabs">
      <button class="auth-tab active" onclick="switchAuthTab('login')">Sign In</button>
      <button class="auth-tab" onclick="switchAuthTab('register')">Register</button>
    </div>

    <!-- LOGIN -->
    <div class="auth-form active" id="af-login">
      <div class="auth-form-title">Welcome back</div>
      <div class="auth-form-sub">Sign in to access news, events, and bookings.</div>
      <div class="auth-err" id="login-err"></div>
      <div class="form-group"><label>Username</label><input id="l-user" placeholder="Your username" autocomplete="username" onkeydown="if(event.key==='Enter')doLogin()"></div>
      <div class="form-group"><label>Password</label><input id="l-pass" type="password" placeholder="Your password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()"></div>
      <button class="btn btn-p btn-full" style="margin-top:4px" onclick="doLogin()">Sign In</button>
      <div style="margin-top:14px;text-align:center;font-size:12px;color:var(--muted)">
        Don't have an account? <a href="#" style="color:var(--amber);font-weight:600;text-decoration:none" onclick="switchAuthTab('register')">Register here</a>
      </div>
    </div>

    <!-- REGISTER -->
    <div class="auth-form" id="af-register">
      <div class="auth-form-title">Create your account</div>
      <div class="auth-form-sub">Fill in your details to access the portal.</div>
      <div class="auth-err" id="reg-err"></div>
      <div class="form-row">
        <div class="form-group"><label>Full Name</label><input id="r-name" placeholder="e.g. Sarah Ahmed"></div>
        <div class="form-group"><label>Room Number</label><input id="r-room" placeholder="e.g. 204"></div>
      </div>
      <div class="form-group"><label>Username</label><input id="r-user" placeholder="Choose a username" autocomplete="username"></div>
      <div class="form-row">
        <div class="form-group"><label>Password</label><input id="r-pass" type="password" placeholder="Min. 6 characters" autocomplete="new-password"></div>
        <div class="form-group"><label>Confirm Password</label><input id="r-pass2" type="password" placeholder="Repeat password" onkeydown="if(event.key==='Enter')doRegister()"></div>
      </div>
      <button class="btn btn-p btn-full" style="margin-top:4px" onclick="doRegister()">Create Account</button>
      <div style="margin-top:14px;text-align:center;font-size:12px;color:var(--muted)">
        Already have an account? <a href="#" style="color:var(--amber);font-weight:600;text-decoration:none" onclick="switchAuthTab('login')">Sign in</a>
      </div>
    </div>
  </div>
</div>

<!-- APP -->
<div id="app" style="display:none;flex-direction:column;min-height:100vh">

  <header id="topbar">
    <div class="brand" onclick="showPage('dashboard')">
      <div class="brand-icon">🏠</div>Residence Portal
    </div>
    <nav id="nav">
      <button class="nav-btn active" onclick="showPage('dashboard')" data-page="dashboard">Dashboard</button>
      <button class="nav-btn" onclick="showPage('news')" data-page="news">News</button>
      <button class="nav-btn" onclick="showPage('events')" data-page="events">Events</button>
      <button class="nav-btn" onclick="showPage('laundry')" data-page="laundry">Laundry</button>
      <button class="nav-btn" onclick="showPage('equipment')" data-page="equipment">Equipment</button>
      <button class="nav-btn" id="admin-nav-btn" onclick="showPage('admin')" data-page="admin" style="display:none">⚙ Admin</button>
    </nav>
    <div id="user-area">
      <div class="user-chip">
        <div class="user-av" id="user-av">?</div>
        <div class="user-info">
          <div class="user-name" id="user-name-disp">—</div>
          <div class="user-room" id="user-room-disp">—</div>
        </div>
      </div>
      <button class="logout-btn" onclick="doLogout()">Sign Out</button>
    </div>
  </header>

  <div id="notice-banner">
    <div class="notice-inner">
      <span class="notice-icon">📢</span>
      <div id="notice-items"></div>
    </div>
  </div>

  <main>

    <!-- DASHBOARD -->
    <div class="page active" id="page-dashboard">
      <div class="dash-hero">
        <div class="dash-hero-title" id="hero-greeting">Good to see you 👋</div>
        <div class="dash-hero-sub">Welcome to your Residence Portal — news, events, and bookings in one place.</div>
        <div class="dash-hero-date" id="hero-date"></div>
      </div>
      <div class="stats-row">
        <div class="stat-card"><div class="stat-lbl">Announcements</div><div class="stat-val" id="st-news">—</div></div>
        <div class="stat-card"><div class="stat-lbl">Upcoming Events</div><div class="stat-val" id="st-events">—</div></div>
        <div class="stat-card"><div class="stat-lbl">Laundry Bookings</div><div class="stat-val" id="st-laundry">—</div></div>
        <div class="stat-card"><div class="stat-lbl">Equipment</div><div class="stat-val" id="st-equip">—</div></div>
      </div>
      <div class="dash-grid">
        <div>
          <div class="sec-title">Latest Announcements</div>
          <div id="dash-news"></div>
          <button class="btn btn-gh" style="margin-top:14px" onclick="showPage('news')">All news →</button>
        </div>
        <div>
          <div class="sec-title">Upcoming Events</div>
          <div id="dash-events"></div>
          <button class="btn btn-gh" style="margin-top:14px" onclick="showPage('events')">All events →</button>
        </div>
      </div>
    </div>

    <!-- NEWS -->
    <div class="page" id="page-news">
      <div class="page-title">News & Announcements</div>
      <div class="page-sub">Building updates, policy changes, and management notices.</div>
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
      <div class="page-title">Events</div>
      <div class="page-sub">Community gatherings and shared activities.</div>
      <div style="display:flex;gap:10px;margin-bottom:22px;flex-wrap:wrap">
        <button class="btn btn-s" id="ef-all"      onclick="setEvtFilter('all')">All</button>
        <button class="btn btn-gh" id="ef-upcoming" onclick="setEvtFilter('upcoming')">Upcoming</button>
        <button class="btn btn-gh" id="ef-past"     onclick="setEvtFilter('past')">Past</button>
      </div>
      <div class="grid grid-2" id="events-list"></div>
    </div>

    <!-- LAUNDRY -->
    <div class="page" id="page-laundry">
      <div class="page-title">Laundry Booking</div>
      <div class="page-sub">Reserve a washing machine. The 10-minute rule applies after your cycle ends.</div>
      <div style="display:grid;grid-template-columns:1fr 360px;gap:24px;align-items:start" id="laundry-layout">
        <div>
          <div class="sec-title">Make a Reservation</div>
          <div class="adm-sec" style="padding:22px">
            <div class="form-group">
              <label>Booking for</label>
              <div style="background:var(--cream2);border:1.5px solid var(--border);border-radius:var(--r);padding:10px 13px;font-size:14px;color:var(--slate2)" id="lb-identity">—</div>
            </div>
            <div class="form-group">
              <label>Machine</label>
              <div class="machine-tabs">
                <button class="m-tab active" data-m="M1" onclick="selMachine(this)">Machine 1</button>
                <button class="m-tab" data-m="M2" onclick="selMachine(this)">Machine 2</button>
                <button class="m-tab" data-m="M3" onclick="selMachine(this)">Machine 3</button>
              </div>
            </div>
            <div class="form-group"><label>Date</label><input type="date" id="lb-date" onchange="loadSlots()"></div>
            <div class="form-group">
              <label>Time Slot</label>
              <div class="slot-grid" id="lb-slots"><div style="color:var(--muted);font-size:13px">Choose a date above.</div></div>
            </div>
            <input type="hidden" id="lb-slot">
            <button class="btn btn-p btn-full" onclick="bookLaundry()">Confirm Reservation</button>
          </div>
        </div>
        <div>
          <div class="sec-title">All Reservations</div>
          <div class="tbl-wrap">
            <table><thead><tr><th>Name</th><th>Room</th><th>Machine</th><th>Date</th><th>Slot</th><th></th></tr></thead>
            <tbody id="laundry-tbody"></tbody></table>
          </div>
        </div>
      </div>
    </div>

    <!-- EQUIPMENT -->
    <div class="page" id="page-equipment">
      <div class="page-title">Equipment Booking</div>
      <div class="page-sub">Reserve shared equipment. Maximum 1 hour per item per day per resident.</div>
      <div style="display:grid;grid-template-columns:1fr 360px;gap:24px;align-items:start">
        <div>
          <div class="sec-title">Book Equipment</div>
          <div class="adm-sec" style="padding:22px">
            <div class="form-group">
              <label>Booking for</label>
              <div style="background:var(--cream2);border:1.5px solid var(--border);border-radius:var(--r);padding:10px 13px;font-size:14px;color:var(--slate2)" id="eq-identity">—</div>
            </div>
            <div class="form-group"><label>Equipment</label>
              <select id="eq-item">
                <option value="Vacuum Cleaner">🧹 Vacuum Cleaner (max 1hr/day)</option>
                <option value="Ladder">🪜 Ladder</option>
                <option value="Power Drill">🔧 Power Drill</option>
                <option value="Ironing Board">👔 Ironing Board</option>
              </select>
            </div>
            <div class="form-group"><label>Date</label><input type="date" id="eq-date"></div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px">
              <span class="pill pill-a">📋 Max 1 hour per item per day</span>
              <span class="pill pill-s">Return equipment after use</span>
            </div>
            <button class="btn btn-p btn-full" onclick="bookEquip()">Book Equipment</button>
          </div>
        </div>
        <div>
          <div class="sec-title">Current Bookings</div>
          <div class="tbl-wrap">
            <table><thead><tr><th>Name</th><th>Room</th><th>Item</th><th>Date</th><th></th></tr></thead>
            <tbody id="equip-tbody"></tbody></table>
          </div>
        </div>
      </div>
    </div>

    <!-- ADMIN -->
    <div class="page" id="page-admin">
      <div class="page-title">Administration</div>
      <div class="page-sub">Manage notices, news, events, bookings, and residents.</div>

      <div class="adm-sec">
        <h3>📢 Notices</h3>
        <div class="form-row" style="margin-bottom:12px">
          <div class="form-group"><label>Notice Text</label><input id="adm-notice-txt" placeholder="Enter notice…"></div>
          <div class="form-group" style="display:flex;align-items:flex-end;gap:8px;padding-bottom:0">
            <label style="display:flex;align-items:center;gap:6px;font-size:13px;cursor:pointer;margin-bottom:0;text-transform:none;letter-spacing:0">
              <input type="checkbox" id="adm-notice-urg" style="width:auto"> Urgent
            </label>
          </div>
        </div>
        <button class="btn btn-p btn-sm" onclick="addNotice()">Post Notice</button>
        <div class="divider"></div>
        <div id="adm-notices"></div>
      </div>

      <div class="adm-sec">
        <h3>📰 Post News</h3>
        <div class="form-row">
          <div class="form-group"><label>Title</label><input id="adm-news-t" placeholder="Announcement title"></div>
          <div class="form-group"><label>Category</label>
            <select id="adm-news-cat"><option>Kitchen</option><option>Laundry</option><option>Maintenance</option><option>General</option></select>
          </div>
        </div>
        <div class="form-group"><label>Date</label><input type="date" id="adm-news-d" style="max-width:200px"></div>
        <div class="form-group"><label>Content</label><textarea id="adm-news-c" placeholder="Full announcement text…"></textarea></div>
        <button class="btn btn-p" onclick="postNews()">Publish</button>
      </div>

      <div class="adm-sec">
        <h3>🎉 Create Event</h3>
        <div class="form-row">
          <div class="form-group"><label>Event Name</label><input id="adm-evt-n" placeholder="e.g. Game Night"></div>
          <div class="form-group"><label>Location</label><input id="adm-evt-loc" placeholder="e.g. Lounge Area"></div>
        </div>
        <div class="form-row">
          <div class="form-group"><label>Date</label><input type="date" id="adm-evt-d"></div>
          <div class="form-group"><label>Time</label><input type="time" id="adm-evt-t"></div>
        </div>
        <div class="form-group"><label>Max Participants</label><input type="number" id="adm-evt-max" placeholder="20" min="1" style="max-width:120px"></div>
        <div class="form-group"><label>Description</label><textarea id="adm-evt-desc" placeholder="What's happening?"></textarea></div>
        <button class="btn btn-p" onclick="createEvent()">Create Event</button>
      </div>

      <div class="adm-sec"><h3>📋 Manage News</h3><div id="adm-news-list"></div></div>
      <div class="adm-sec"><h3>📋 Manage Events</h3><div id="adm-events-list"></div></div>

      <div class="adm-sec">
        <h3>👥 Registered Residents</h3>
        <div class="tbl-wrap">
          <table><thead><tr><th>Name</th><th>Room</th><th>Username</th><th>Role</th><th>Joined</th><th></th></tr></thead>
          <tbody id="adm-users-tbody"></tbody></table>
        </div>
      </div>

      <div class="adm-sec">
        <h3>🧺 All Laundry Bookings</h3>
        <div class="tbl-wrap">
          <table><thead><tr><th>Name</th><th>Room</th><th>Machine</th><th>Date</th><th>Slot</th><th></th></tr></thead>
          <tbody id="adm-laundry-tbody"></tbody></table>
        </div>
      </div>
      <div class="adm-sec">
        <h3>🔧 All Equipment Bookings</h3>
        <div class="tbl-wrap">
          <table><thead><tr><th>Name</th><th>Room</th><th>Item</th><th>Date</th><th></th></tr></thead>
          <tbody id="adm-equip-tbody"></tbody></table>
        </div>
      </div>
    </div>

  </main>
</div>

<div id="toasts"></div>

<script>
// ── STATE ────────────────────────────────────────────────
let token='', currentUser=null;
let allNews=[], allEvents=[], allLaundry=[], allEquip=[], allNotices=[];
let evtFilter='all', selMachineId='M1', selSlot='';

// ── AUTH STORAGE ─────────────────────────────────────────
function saveAuth(t,u){token=t;currentUser=u;try{localStorage.setItem('res_token',t);localStorage.setItem('res_user',JSON.stringify(u));}catch(e){}}
function loadAuth(){try{token=localStorage.getItem('res_token')||'';const u=localStorage.getItem('res_user');if(u)currentUser=JSON.parse(u);}catch(e){}}
function clearAuth(){token='';currentUser=null;try{localStorage.removeItem('res_token');localStorage.removeItem('res_user');}catch(e){}}

// ── API ──────────────────────────────────────────────────
async function api(method,path,body){
  try{
    const opts={method,headers:{'Content-Type':'application/json'}};
    if(token)opts.headers['Authorization']='Bearer '+token;
    if(body)opts.body=JSON.stringify(body);
    const r=await fetch(path,opts);
    return await r.json();
  }catch(e){toast('Connection error','er');return null;}
}
const GET=(p)=>api('GET',p);
const POST=(p,b)=>api('POST',p,b);
const PUT=(p,b)=>api('PUT',p,b);
const DEL=(p)=>api('DELETE',p);

// ── SSE ──────────────────────────────────────────────────
let sse=null;
function connectSSE(){
  if(sse)sse.close();
  sse=new EventSource('/api/stream?token='+token);
  sse.addEventListener('notices', e=>{allNotices=JSON.parse(e.data);renderNotices();});
  sse.addEventListener('news',    ()=>loadNews());
  sse.addEventListener('news-deleted',()=>loadNews());
  sse.addEventListener('events',  e=>{allEvents=JSON.parse(e.data);renderEvents();renderDashEvents();updateStats();});
  sse.addEventListener('laundry', e=>{allLaundry=JSON.parse(e.data);renderLaundryTable();renderAdminLaundry();loadSlots();updateStats();});
  sse.addEventListener('equipment',e=>{allEquip=JSON.parse(e.data);renderEquipTable();renderAdminEquip();updateStats();});
  sse.onerror=()=>{};
}

// ── AUTH UI ──────────────────────────────────────────────
function switchAuthTab(t){
  document.querySelectorAll('.auth-tab').forEach((b,i)=>b.classList.toggle('active',(t==='login'&&i===0)||(t==='register'&&i===1)));
  document.getElementById('af-login').classList.toggle('active',t==='login');
  document.getElementById('af-register').classList.toggle('active',t==='register');
  document.getElementById('login-err').classList.remove('show');
  document.getElementById('reg-err').classList.remove('show');
}
function showAuthErr(id,msg){const el=document.getElementById(id);el.textContent=msg;el.classList.add('show');}

async function doLogin(){
  const u=document.getElementById('l-user').value.trim();
  const p=document.getElementById('l-pass').value;
  if(!u||!p){showAuthErr('login-err','Please enter your username and password.');return;}
  const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});
  const data=await r.json();
  if(data.error){showAuthErr('login-err',data.error);return;}
  saveAuth(data.token,data.user);
  bootApp();
}

async function doRegister(){
  const name=document.getElementById('r-name').value.trim();
  const room=document.getElementById('r-room').value.trim();
  const uname=document.getElementById('r-user').value.trim();
  const pw=document.getElementById('r-pass').value;
  const pw2=document.getElementById('r-pass2').value;
  if(!name||!room||!uname||!pw){showAuthErr('reg-err','All fields are required.');return;}
  if(pw!==pw2){showAuthErr('reg-err','Passwords do not match.');return;}
  if(pw.length<6){showAuthErr('reg-err','Password must be at least 6 characters.');return;}
  const r=await fetch('/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,room,username:uname,password:pw})});
  const data=await r.json();
  if(data.error){showAuthErr('reg-err',data.error);return;}
  saveAuth(data.token,data.user);
  bootApp();
}

async function doLogout(){
  await POST('/api/auth/logout');
  clearAuth(); if(sse)sse.close();
  document.getElementById('auth-screen').style.display='flex';
  document.getElementById('app').style.display='none';
  document.getElementById('l-user').value='';
  document.getElementById('l-pass').value='';
}

// ── BOOT ─────────────────────────────────────────────────
async function bootApp(){
  document.getElementById('auth-screen').style.display='none';
  document.getElementById('app').style.display='flex';
  // Update user display
  document.getElementById('user-name-disp').textContent=currentUser.name;
  document.getElementById('user-room-disp').textContent='Room '+currentUser.room;
  document.getElementById('user-av').textContent=(currentUser.name[0]||'?').toUpperCase();
  document.getElementById('hero-greeting').textContent='Welcome back, '+currentUser.name.split(' ')[0]+' 👋';
  document.getElementById('hero-date').textContent=new Date().toLocaleDateString('en-GB',{weekday:'long',day:'numeric',month:'long',year:'numeric'});
  // Show admin nav if admin
  document.getElementById('admin-nav-btn').style.display=currentUser.role==='admin'?'':'none';
  // Pre-fill identity labels
  const iLabel=currentUser.name+' — Room '+currentUser.room;
  document.getElementById('lb-identity').textContent=iLabel;
  document.getElementById('eq-identity').textContent=iLabel;
  // Set today's date
  const td=new Date().toISOString().split('T')[0];
  document.getElementById('lb-date').value=td;
  document.getElementById('eq-date').value=td;
  document.getElementById('adm-news-d').value=td;
  connectSSE();
  await Promise.all([loadNews(),loadEvents(),loadLaundry(),loadEquip(),loadNotices()]);
  if(currentUser.role==='admin')loadAdminUsers();
}

// ── CHECK EXISTING SESSION ────────────────────────────────
async function checkSession(){
  loadAuth();
  if(!token){return;}
  const r=await fetch('/api/auth/me',{headers:{'Authorization':'Bearer '+token}});
  if(r.status===200){
    currentUser=await r.json();
    bootApp();
  } else {
    clearAuth();
  }
}

// ── DATA LOADERS ─────────────────────────────────────────
async function loadNews(){const d=await GET('/api/news');if(d&&Array.isArray(d)){allNews=d;renderNews();renderDashNews();updateStats();}}
async function loadEvents(){const d=await GET('/api/events');if(d&&Array.isArray(d)){allEvents=d;renderEvents();renderDashEvents();renderAdminEvents();updateStats();}}
async function loadLaundry(){const d=await GET('/api/laundry');if(d&&Array.isArray(d)){allLaundry=d;renderLaundryTable();renderAdminLaundry();loadSlots();updateStats();}}
async function loadEquip(){const d=await GET('/api/equipment');if(d&&Array.isArray(d)){allEquip=d;renderEquipTable();renderAdminEquip();updateStats();}}
async function loadNotices(){const d=await GET('/api/notices');if(d&&Array.isArray(d)){allNotices=d;renderNotices();}}
async function loadAdminUsers(){const d=await GET('/api/users');if(d&&Array.isArray(d))renderAdminUsers(d);}

// ── STATS ────────────────────────────────────────────────
function updateStats(){
  const up=allEvents.filter(e=>e.date>=today()).length;
  document.getElementById('st-news').textContent=allNews.length;
  document.getElementById('st-events').textContent=up;
  document.getElementById('st-laundry').textContent=allLaundry.length;
  document.getElementById('st-equip').textContent=allEquip.length;
}
const today=()=>new Date().toISOString().split('T')[0];
const fmt=d=>new Date(d+'T00:00:00').toLocaleDateString('en-GB',{weekday:'short',day:'numeric',month:'short',year:'numeric'});
const fmtS=d=>new Date(d+'T00:00:00').toLocaleDateString('en-GB',{day:'numeric',month:'short'});

// ── NOTICES ──────────────────────────────────────────────
function renderNotices(){
  const b=document.getElementById('notice-banner'),el=document.getElementById('notice-items');
  if(!allNotices.length){b.classList.remove('show');return;}
  b.classList.add('show');
  el.innerHTML=allNotices.map(n=>`<div class="n-item${n.urgent?' n-urgent':''}">${n.urgent?'⚠ ':''}${esc(n.text)}</div>`).join('');
}
function renderAdminNotices(){
  const el=document.getElementById('adm-notices');
  if(!allNotices.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No active notices.</div>';return;}
  el.innerHTML=allNotices.map(n=>`<div class="adm-row"><div class="adm-info"><strong>${n.urgent?'⚠ ':''}${esc(n.text)}</strong><small>${n.urgent?'Urgent':'General'}</small></div><button class="btn btn-r btn-sm" onclick="delNotice('${n.id}')">Remove</button></div>`).join('');
}
async function addNotice(){
  const txt=document.getElementById('adm-notice-txt').value.trim();
  const urg=document.getElementById('adm-notice-urg').checked;
  if(!txt){toast('Please enter notice text','er');return;}
  const r=await POST('/api/notices',{text:txt,urgent:urg});
  if(r&&r.id){document.getElementById('adm-notice-txt').value='';document.getElementById('adm-notice-urg').checked=false;toast('Notice posted','ok');loadNotices();}
}
async function delNotice(id){await DEL('/api/notices/'+id);toast('Notice removed');loadNotices();}

// ── NEWS ─────────────────────────────────────────────────
const catBadge=c=>{ const m={Kitchen:'kitchen',Laundry:'laundry',Maintenance:'maintenance',General:'general'}; return`<span class="badge b-${m[c]||'general'}">${c}</span>`; };

function renderNews(){
  const q=(document.getElementById('news-q')||{value:''}).value.toLowerCase();
  const cat=(document.getElementById('news-cat')||{value:''}).value;
  let list=allNews.filter(n=>{
    const mq=!q||n.title.toLowerCase().includes(q)||n.content.toLowerCase().includes(q);
    const mc=!cat||n.category===cat;
    return mq&&mc;
  });
  const el=document.getElementById('news-list');
  if(!list.length){el.innerHTML='<div class="empty"><span class="empty-icon">📄</span>No announcements found.</div>';return;}
  el.innerHTML=list.map(n=>`<div class="card news-card"><div class="nc-meta">${catBadge(n.category)}<span class="nc-date">${fmt(n.date)}</span></div><div class="nc-title">${esc(n.title)}</div><div class="nc-body">${esc(n.content)}</div></div>`).join('');
}

function renderDashNews(){
  const el=document.getElementById('dash-news');
  const list=allNews.slice(0,3);
  if(!list.length){el.innerHTML='<div class="empty"><span class="empty-icon">📄</span>No news yet.</div>';return;}
  el.innerHTML=list.map(n=>`<div class="card news-card" style="margin-bottom:12px"><div class="nc-meta">${catBadge(n.category)}<span class="nc-date">${fmtS(n.date)}</span></div><div class="nc-title" style="font-size:15px">${esc(n.title)}</div><div class="nc-body" style="font-size:13px;display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:2;overflow:hidden">${esc(n.content)}</div></div>`).join('');
}

function renderAdminNews(){
  const el=document.getElementById('adm-news-list');
  if(!allNews.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No news items.</div>';return;}
  el.innerHTML=allNews.map(n=>`<div class="adm-row"><div class="adm-info"><strong>${esc(n.title)}</strong><small>${catBadge(n.category)} ${fmt(n.date)}</small></div><button class="btn btn-r btn-sm" onclick="delNews('${n.id}')">Delete</button></div>`).join('');
}
async function postNews(){
  const title=document.getElementById('adm-news-t').value.trim();
  const cat=document.getElementById('adm-news-cat').value;
  const date=document.getElementById('adm-news-d').value||today();
  const content=document.getElementById('adm-news-c').value.trim();
  if(!title||!content){toast('Title and content required','er');return;}
  const r=await POST('/api/news',{title,category:cat,date,content});
  if(r&&r.id){['adm-news-t','adm-news-c'].forEach(id=>document.getElementById(id).value='');toast('Published!','ok');loadNews();}
}
async function delNews(id){if(!confirm('Delete this news item?'))return;await DEL('/api/news/'+id);toast('Deleted');loadNews();}

// ── EVENTS ───────────────────────────────────────────────
function setEvtFilter(f){
  evtFilter=f;
  ['all','upcoming','past'].forEach(x=>{
    document.getElementById('ef-'+x).className='btn '+(x===f?'btn-s':'btn-gh');
  });
  renderEvents();
}
function renderEvents(){
  let list=[...allEvents];
  if(evtFilter==='upcoming')list=list.filter(e=>e.date>=today());
  if(evtFilter==='past')list=list.filter(e=>e.date<today());
  list.sort((a,b)=>a.date.localeCompare(b.date));
  const el=document.getElementById('events-list');
  if(!list.length){el.innerHTML='<div class="empty"><span class="empty-icon">📅</span>No events found.</div>';return;}
  el.innerHTML=list.map(e=>evtCard(e,true)).join('');
}
function renderDashEvents(){
  const list=allEvents.filter(e=>e.date>=today()).sort((a,b)=>a.date.localeCompare(b.date)).slice(0,3);
  const el=document.getElementById('dash-events');
  if(!list.length){el.innerHTML='<div class="empty"><span class="empty-icon">📅</span>No upcoming events.</div>';return;}
  el.innerHTML=list.map(e=>evtCard(e,false)).join('');
}
function renderAdminEvents(){
  const el=document.getElementById('adm-events-list');
  if(!allEvents.length){el.innerHTML='<div style="color:var(--muted);font-size:13px">No events.</div>';return;}
  el.innerHTML=allEvents.map(e=>`<div class="adm-row"><div class="adm-info"><strong>${esc(e.name)}</strong><small>${fmt(e.date)} at ${e.time} — ${e.participants.length}/${e.maxParticipants} registered</small></div><button class="btn btn-r btn-sm" onclick="delEvent('${e.id}')">Delete</button></div>`).join('');
}

function evtCard(e,showReg){
  const up=e.date>=today(), full=e.participants.length>=e.maxParticipants;
  const pct=Math.min(100,Math.round(e.participants.length/e.maxParticipants*100));
  const rid='reg-'+e.id;
  const myLabel=currentUser?currentUser.name+' (Room '+currentUser.room+')':'';
  const registered=e.participants.includes(myLabel);
  return`<div class="card event-card${!up?' past':''}">
    <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:6px">
      <div class="evt-name">${esc(e.name)}</div>
      ${up?(full?'<span class="badge b-full">Full</span>':'<span class="badge b-upcoming">Upcoming</span>'):'<span class="badge b-past">Past</span>'}
    </div>
    <div class="evt-meta">
      <span>📅 ${fmt(e.date)}</span><span>🕐 ${e.time}</span><span>📍 ${esc(e.location)}</span>
    </div>
    <div class="evt-desc">${esc(e.description)}</div>
    <div class="evt-footer">
      <div style="font-size:13px;color:var(--muted)">${e.participants.length}/${e.maxParticipants} participants<span class="cap-bar"><span class="cap-fill${full?' full':''}" style="width:${pct}%"></span></span></div>
      ${up&&showReg?`<button class="btn btn-sm ${registered?'btn-gh':'btn-g'}" onclick="toggleReg('${rid}')">${registered?'Manage Registration':'Register'}</button>`:''}
    </div>
    ${up&&showReg?`<div class="reg-section" id="${rid}">
      <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
        <span style="font-size:13px;color:var(--muted)">Registering as: <strong style="color:var(--slate)">${esc(myLabel)}</strong></span>
      </div>
      <div style="display:flex;gap:8px;margin-top:12px;flex-wrap:wrap">
        ${!registered&&!full?`<button class="btn btn-g btn-sm" onclick="regEvent('${e.id}',false)">✓ Confirm Registration</button>`:''}
        ${registered?`<button class="btn btn-gh btn-sm" onclick="regEvent('${e.id}',true)">✕ Cancel Registration</button>`:''}
      </div>
    </div>`:''}
  </div>`;
}
function toggleReg(id){const el=document.getElementById(id);if(el)el.classList.toggle('open');}

async function regEvent(evtId,cancel){
  const r=await POST('/api/events/'+evtId+'/register',{cancel});
  if(r&&r.id){toast(cancel?'Registration cancelled':'Registered!','ok');loadEvents();}
  else if(r&&r.error)toast(r.error,'er');
}

async function createEvent(){
  const name=document.getElementById('adm-evt-n').value.trim();
  const date=document.getElementById('adm-evt-d').value;
  const time=document.getElementById('adm-evt-t').value||'18:00';
  const loc=document.getElementById('adm-evt-loc').value.trim()||'TBD';
  const max=document.getElementById('adm-evt-max').value||20;
  const desc=document.getElementById('adm-evt-desc').value.trim();
  if(!name||!date){toast('Name and date required','er');return;}
  const r=await POST('/api/events',{name,date,time,location:loc,maxParticipants:parseInt(max),description:desc});
  if(r&&r.id){['adm-evt-n','adm-evt-d','adm-evt-t','adm-evt-loc','adm-evt-max','adm-evt-desc'].forEach(id=>document.getElementById(id).value='');toast('Event created!','ok');loadEvents();}
}
async function delEvent(id){if(!confirm('Delete this event?'))return;await DEL('/api/events/'+id);toast('Deleted');loadEvents();}

// ── LAUNDRY ──────────────────────────────────────────────
const SLOTS=['07:00','08:00','09:00','10:00','11:00','12:00','13:00','14:00','15:00','16:00','17:00','18:00','19:00','20:00','21:00','22:00'];

function selMachine(btn){
  document.querySelectorAll('.m-tab').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active'); selMachineId=btn.dataset.m; loadSlots();
}
function loadSlots(){
  const date=document.getElementById('lb-date').value;
  const el=document.getElementById('lb-slots');
  if(!date){el.innerHTML='<div style="color:var(--muted);font-size:13px">Choose a date above.</div>';return;}
  const taken=allLaundry.filter(b=>b.machineId===selMachineId&&b.date===date).map(b=>b.slot);
  el.innerHTML=SLOTS.map(s=>{
    const t=taken.includes(s), sel=s===selSlot;
    return`<div class="slot${t?' taken':sel?' selected':''}" onclick="${t?'':'selectSlot(this,\''+s+'\')'}">${s}${t?'<br><small>Taken</small>':''}</div>`;
  }).join('');
}
function selectSlot(el,slot){
  selSlot=slot;document.getElementById('lb-slot').value=slot;
  document.querySelectorAll('.slot').forEach(s=>s.classList.remove('selected'));
  el.classList.add('selected');
}
async function bookLaundry(){
  const date=document.getElementById('lb-date').value;
  const slot=document.getElementById('lb-slot').value;
  if(!date||!slot){toast('Please select a date and time slot','er');return;}
  const r=await POST('/api/laundry',{machineId:selMachineId,date,slot});
  if(r&&r.id){selSlot='';document.getElementById('lb-slot').value='';toast('Booked!','ok');loadLaundry();}
  else if(r&&r.error)toast(r.error,'er');
}
function renderLaundryTable(){
  const tbody=document.getElementById('laundry-tbody');
  if(!allLaundry.length){tbody.innerHTML='<tr><td class="tbl-empty" colspan="6">No reservations yet.</td></tr>';return;}
  const sorted=[...allLaundry].sort((a,b)=>a.date.localeCompare(b.date)||a.slot.localeCompare(b.slot));
  tbody.innerHTML=sorted.map(b=>{
    const mine=currentUser&&(b.userId===currentUser.id||currentUser.role==='admin');
    return`<tr><td>${esc(b.name)}</td><td>${esc(b.room)}</td><td>${esc(b.machineId)}</td><td>${fmtS(b.date)}</td><td>${b.slot}</td><td>${mine?`<button class="btn btn-r btn-sm" onclick="cancelLaundry('${b.id}')">Cancel</button>`:''}</td></tr>`;
  }).join('');
  loadSlots();
}
function renderAdminLaundry(){
  const tbody=document.getElementById('adm-laundry-tbody');
  if(!allLaundry.length){tbody.innerHTML='<tr><td class="tbl-empty" colspan="6">No bookings.</td></tr>';return;}
  tbody.innerHTML=[...allLaundry].sort((a,b)=>a.date.localeCompare(b.date)).map(b=>`<tr><td>${esc(b.name)}</td><td>${esc(b.room)}</td><td>${esc(b.machineId)}</td><td>${fmtS(b.date)}</td><td>${b.slot}</td><td><button class="btn btn-r btn-sm" onclick="cancelLaundry('${b.id}')">Del</button></td></tr>`).join('');
}
async function cancelLaundry(id){if(!confirm('Cancel this booking?'))return;await DEL('/api/laundry/'+id);toast('Cancelled');loadLaundry();}

// ── EQUIPMENT ────────────────────────────────────────────
async function bookEquip(){
  const item=document.getElementById('eq-item').value;
  const date=document.getElementById('eq-date').value||today();
  const r=await POST('/api/equipment',{item,date});
  if(r&&r.id){toast('Equipment booked! Max 1 hour — return after use.','ok');loadEquip();}
  else if(r&&r.error)toast(r.error,'er');
}
function renderEquipTable(){
  const tbody=document.getElementById('equip-tbody');
  if(!allEquip.length){tbody.innerHTML='<tr><td class="tbl-empty" colspan="5">No bookings.</td></tr>';return;}
  tbody.innerHTML=[...allEquip].sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(b=>{
    const mine=currentUser&&(b.userId===currentUser.id||currentUser.role==='admin');
    return`<tr><td>${esc(b.name)}</td><td>${esc(b.room)}</td><td>${esc(b.item)}</td><td>${fmtS(b.date)}</td><td>${mine?`<button class="btn btn-r btn-sm" onclick="cancelEquip('${b.id}')">Cancel</button>`:''}</td></tr>`;
  }).join('');
}
function renderAdminEquip(){
  const tbody=document.getElementById('adm-equip-tbody');
  if(!allEquip.length){tbody.innerHTML='<tr><td class="tbl-empty" colspan="5">No bookings.</td></tr>';return;}
  tbody.innerHTML=[...allEquip].sort((a,b)=>b.createdAt.localeCompare(a.createdAt)).map(b=>`<tr><td>${esc(b.name)}</td><td>${esc(b.room)}</td><td>${esc(b.item)}</td><td>${fmtS(b.date)}</td><td><button class="btn btn-r btn-sm" onclick="cancelEquip('${b.id}')">Del</button></td></tr>`).join('');
}
async function cancelEquip(id){if(!confirm('Cancel this booking?'))return;await DEL('/api/equipment/'+id);toast('Cancelled');loadEquip();}

// ── ADMIN USERS ───────────────────────────────────────────
function renderAdminUsers(users){
  const tbody=document.getElementById('adm-users-tbody');
  if(!users.length){tbody.innerHTML='<tr><td class="tbl-empty" colspan="6">No users.</td></tr>';return;}
  tbody.innerHTML=users.map(u=>`<tr>
    <td>${esc(u.name)}</td><td>${esc(u.room)}</td><td>${esc(u.username)}</td>
    <td><span class="badge ${u.role==='admin'?'b-general':'b-upcoming'}">${u.role}</span></td>
    <td style="font-size:12px;color:var(--muted)">${u.createdAt.split('T')[0]}</td>
    <td>${u.role!=='admin'?`<button class="btn btn-r btn-sm" onclick="delUser('${u.id}')">Remove</button>`:''}</td>
  </tr>`).join('');
}
async function delUser(id){if(!confirm('Remove this resident?'))return;const r=await DEL('/api/users/'+id);if(r&&r.success){toast('Resident removed','ok');loadAdminUsers();}else if(r&&r.error)toast(r.error,'er');}

// ── NAVIGATION ────────────────────────────────────────────
function showPage(name){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  document.getElementById('page-'+name).classList.add('active');
  const btn=document.querySelector('[data-page="'+name+'"]');
  if(btn)btn.classList.add('active');
  window.scrollTo(0,0);
  if(name==='admin'){renderAdminNews();renderAdminEvents();renderAdminNotices();loadAdminUsers();}
}

// ── TOAST ─────────────────────────────────────────────────
function toast(msg,type=''){
  const icons={ok:'✓',er:'✕','':''};
  const el=document.createElement('div');
  el.className='toast'+(type?' '+type:'');
  el.innerHTML=(icons[type]?'<span>'+icons[type]+'</span>':'')+`<span>${msg}</span>`;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>el.remove(),3500);
}

// ── UTILS ─────────────────────────────────────────────────
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── INIT ─────────────────────────────────────────────────
checkSession();
</script>
</body>
</html>
)HTMLEOF";
}
