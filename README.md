# Kiterioc

A multiplatform IOC hunter for Cyber Threat Intelligence. 

What is Cyber Threat Intelligence?

Cyber Threat Intelligence (CTI) is the collection and analysis of information about threats and adversaries and drawing patterns that provide an ability to make knowledgeable decisions for the preparedness, prevention and response actions against various cyber attacks.

CTI involves collecting, researching and analyzing trends and technical developments in the area of cyber threats and if often presented in the form of Indicators of Compromise (IoCs) or threat feeds, provides evidence-base knowledge regarding an organization's unique threat landscape.

In Cyber Threat Intelligence, analysis if performed based on the intent, capability and opportunity triad. With the study of this triad, experts can evaluate and make informed, forward-learning strategic, operational and tactical decisions on existing or emerging threats to the organization.


Types of Threat Intelligence:

    Strategic Intel: High-level intel that looks into the organisation’s threat landscape and maps out the risk areas based on trends, patterns and emerging threats that may impact business decisions.

    Technical Intel: Looks into evidence and artefacts of attack used by an adversary. Incident Response teams can use this intel to create a baseline attack surface to analyse and develop defence mechanisms.

    Tactical Intel: Assesses adversaries’ tactics, techniques, and procedures (TTPs). This intel can strengthen security controls and address vulnerabilities through real-time investigations.

    Operational Intel: Looks into an adversary’s specific motives and intent to perform an attack. Security teams may use this intel to understand the critical assets available in the organisation (people, processes and technologies) that may be targeted.


Typical sources of intelligence are:

    Open Source Intelligence (OSINT)
    Human Intelligence
    Counter Intelligence
    Internal Intelligence


The primary goal of CTI is to understand the relationship between your operational environment and your adversary and how to defend your environment against any attacks. You would seek this goal by developing your cyber threat context by trying to answer the following questions:

    Who’s attacking you?
    What are their motivations?
    What are their capabilities?
    What artefacts and indicators of compromise (IOCs) should you look out for?



CTI Lifecycle

Direction
Collection
Processing
Analysis
Dissemination
Feedback


CTI Standards & Frameworks 

Mitre att&ck
TAXII
STIX
Cyber kill chain
Diamond model







Some regex patterns are overdoing it: better safe than sorry though!

Data measurement units can be classified into the following:

    Bit - The smallest unit of computer data measurement. Has the value of 0 or 1, which correspond to electronic values of on or off.
    Byte - Contains 8 bits and enough information to form and store at least a single ASCII character, for e.g. 'a'.
    KiloByte - Contains about 1024 Bytes.
    MegaBytes - Contains about 1024 KiloBytes.
    GigaBytes - Contains about 1024 MegaBytes.

There are larger units of data measurement as well. The following units have been used in this project.
KiloByte (KB) 	1024 Bytes
MegaByte (MB) 	1024 KiloBytes
GigaByte (GB) 	1024 MegaBytes

Output is in 'GB', you can easily modify sysinfo.py to any other unit.


USAGE:
        sudo python3 kiterioc.py -flags
EXAMPLE
          sudo python3 kiterioc.py -f .

          sudo python3 kiterioc.py -b -hash e7088a7c37429bd7a1e09dfd05f5052f

          sudo python3 kiterioc.py -b -ip 192.168.23.244

          sudo python3 kiterioc.py -b -url http://abc.hostname.com/somethings/anything/