/*
 * process.cpp
 *
 * Copyright (c) 2004,2005,2008,2011 Arnout Engelen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 *USA.
 *
 */

#include <iostream>
#include <ncurses.h>
#include <string>
#include <strings.h>
#if !defined(__APPLE__) && !defined(__FreeBSD__)
#include <asm/types.h>
#endif
#include <map>
#include <pwd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "conninode.h"
#include "inode2prog.h"
#include "nethogs.h"
#include "process.h"

extern timeval curtime;
extern bool catchall;
/*
 * connection-inode table. takes information from /proc/net/tcp.
 * key contains source ip, source port, destination ip, destination
 * port in format: '1.2.3.4:5-1.2.3.4:5'
 */
extern std::map<std::string, unsigned long> conninode;

/* this file includes:
 * - calls to inodeproc to get the pid that belongs to that inode
 */

/*
 * Initialise the global process-list with some special processes:
 * * unknown TCP traffic
 * * UDP traffic
 * * unknown IP traffic
 * We must take care these never get removed from the list.
 */
Process *unknowntcp;
Process *unknownudp;
Process *unknownip;
ProcList *processes;

#define KB (1UL << 10)
#define MB (1UL << 20)
#define GB (1UL << 30)

float tomb(u_int64_t bytes) { return ((double)bytes) / MB; }
float tokb(u_int64_t bytes) { return ((double)bytes) / KB; }

float tokbps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / KB; }
float tombps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / MB; }
float togbps(u_int64_t bytes) { return (((double)bytes) / PERIOD) / GB; }

void process_init() {
  unknowntcp = new Process(0, "", "unknown TCP");
  processes = new ProcList(unknowntcp, NULL);

  if (catchall) {
    unknownudp = new Process(0, "", "unknown UDP");
    processes = new ProcList(unknownudp, processes);
    // unknownip = new Process (0, "", "unknown IP");
    // processes = new ProcList (unknownip, processes);
  }
}

int Process::getLastPacket() {
  int lastpacket = 0;
  ConnList *curconn = connections;
  while (curconn != NULL) {
    assert(curconn != NULL);
    assert(curconn->getVal() != NULL);
    if (curconn->getVal()->getLastPacket() > lastpacket)
      lastpacket = curconn->getVal()->getLastPacket();
    curconn = curconn->getNext();
  }
  return lastpacket;
}
/*
// #TODO add support also for converting and printing IPv6 
void print_statistics_about_connection(Connection *conn)
{
  char str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(conn->refpacket->sip), str, INET_ADDRSTRLEN);
  std::cout << "Source IP = " << str << std::endl;
  inet_ntop(AF_INET, &(conn->refpacket->dip), str, INET_ADDRSTRLEN);
  std::cout << "Destination IP = " << str << std::endl;
  std::cout << "Source Port = " << conn->refpacket->sport << std::endl;
  std::cout << "Dest Port = " << conn->refpacket->dport << std::endl;
  std::cout << "Total Bytes Sent = " << conn->sumSent << std::endl;
  std::cout << "Total Bytes Received = " << conn->sumRecv << std::endl;
  std::cout << "----------------------------" << std::endl;
}
*/
/*
void print_statistics_about_process(Process *process_ptr)
{
  ConnList *curconn = process_ptr->connections; // A Connection List
  Connection *con;
  std::cout << "Process with the following fields: \n" << std::endl;
  std::cout << "name = " << process_ptr->name << std::endl;
  std::cout << "device name = " << process_ptr->devicename << std::endl;
  std::cout << "process pid = " << process_ptr->pid << std::endl;
  std::cout << "cmdline = " << process_ptr->cmdline << std::endl;
  std::cout << "aggregated connections sent closed bytes = " << process_ptr->sent_by_closed_bytes << std::endl;
  std::cout << "aggregated connections received by closed bytes = " << process_ptr->rcvd_by_closed_bytes << std::endl;
  
  // Printing all information about "Active Connections" (which were not yet killed of the process) 
  std::cout << "\nThat Process has the following Connections: \n----------------\n" << std::endl;
  while(curconn != NULL)
  {
    con = curconn->getVal();
    print_statistics_about_connection(con);
    curconn = curconn->getNext();
  }
}
*/
/*
// #TODO - support for converting and printing IPv6
// #TODO - make the output of this function generic so it will be capable of printing results into a file or to a standard output
void print_closed_connection_info(Process *process_ptr, Connection *conn_todelete)
{
  char str[INET_ADDRSTRLEN];
  std::cout << "Removing a 'timeout connection' from Process" << std::endl;
  std::cout << "--Process Info--" << std::endl;
  std::cout << "Process name = " << process_ptr->name << std::endl;
  std::cout << "Process devicename = " << process_ptr->devicename << std::endl;
  std::cout << "Process PID = " << process_ptr->pid << std::endl;
  std::cout << "Process UID = " << process_ptr->getUid() << std::endl;
  std::cout << "--Connection Info--" << std::endl;
  inet_ntop(AF_INET, &(conn_todelete->refpacket->sip), str, INET_ADDRSTRLEN);
  std::cout << "Source IP = " << str << std::endl;
  std::cout << "Source Port = " << conn_todelete->refpacket->sport << std::endl;
  inet_ntop(AF_INET, &(conn_todelete->refpacket->dip), str, INET_ADDRSTRLEN);
  std::cout << "Destination IP = " << str << std::endl;
  std::cout << "Destination Port = " << conn_todelete->refpacket->dport << std::endl;
  std::cout << "Connection Sent Bytes = " << conn_todelete->sumSent << std::endl;
  std::cout << "Connection Received Bytes = " << conn_todelete->sumRecv << std::endl;
  std::cout << "Done removing the connection\n" << std::endl;
}
*/
// Getting INFROMATION about ALL ACTIVE CONNECTIONS of a PROCESS //
/** get total values for this process for only active connections */
static void sum_active_connections(Process *process_ptr, u_int64_t &sum_sent,
                                   u_int64_t &sum_recv) {
  /* walk though all process_ptr process's connections, and sum
   * them up */
  ConnList *curconn = process_ptr->connections;
  ConnList *previous = NULL;
  //print_statistics_about_process(process_ptr);
  while (curconn != NULL) {// go over all the connections...
    // "curconn->getVal()" --- gives a current "Connection"	  
    if (curconn->getVal()->getLastPacket() <= curtime.tv_sec - CONNTIMEOUT) {
      /* Remove all connections that already have a CONNECTION TIMEOUT */
      /* capture sent and received totals before deleting */
      process_ptr->sent_by_closed_bytes += curconn->getVal()->sumSent;
      process_ptr->rcvd_by_closed_bytes += curconn->getVal()->sumRecv;
      /* stalled connection, remove. */
      /* A pointer to the ConnList itself */
      ConnList *todelete = curconn;
      /* A pointer to the Value of the ConnList --> A Connection Object */
      Connection *conn_todelete = curconn->getVal();
      curconn = curconn->getNext();
      /* taking care of the fact that it may be the first one */
      if (todelete == process_ptr->connections)
        process_ptr->connections = curconn;
      if (previous != NULL)
        previous->setNext(curconn);
      process_ptr->addToList(conn_todelete); // adding the connection to be deleted to the Linked List of the connections summary
      delete (todelete);
      //std::cout << "Deletion of conn_list was successful" << std::endl;
      //std::cout << "Trying to print closed connection info" << std::endl;
      //print_closed_connection_info(process_ptr, conn_todelete);// TODO this can cause problems because "todelete" was already removed
      delete (conn_todelete);
    } else {
      u_int64_t sent = 0, recv = 0;
      curconn->getVal()->sumanddel(curtime, &recv, &sent);
      sum_sent += sent;
      sum_recv += recv;
      previous = curconn;
      curconn = curconn->getNext();
    }
  }
}

/** Get the kb/s values for this process */
void Process::getkbps(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;

  sum_active_connections(this, sum_sent, sum_recv);
  *recvd = tokbps(sum_recv);
  *sent = tokbps(sum_sent);
}

/** Get the mb/s values for this process */
void Process::getmbps(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;

  sum_active_connections(this, sum_sent, sum_recv);
  *recvd = tombps(sum_recv);
  *sent = tombps(sum_sent);
}

/** Get the gb/s values for this process */
void Process::getgbps(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;

  sum_active_connections(this, sum_sent, sum_recv);
  *recvd = togbps(sum_recv);
  *sent = togbps(sum_sent);
}

/** get total values for this process */
void Process::gettotal(u_int64_t *recvd, u_int64_t *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  ConnList *curconn = this->connections;
  while (curconn != NULL) {
    Connection *conn = curconn->getVal();
    sum_sent += conn->sumSent;
    sum_recv += conn->sumRecv;
    curconn = curconn->getNext();
  }
  // std::cout << "Sum sent: " << sum_sent << std::endl;
  // std::cout << "Sum recv: " << sum_recv << std::endl;
  *recvd = sum_recv + this->rcvd_by_closed_bytes;
  *sent = sum_sent + this->sent_by_closed_bytes;
}

void Process::gettotalmb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tomb(sum_recv);
  *sent = tomb(sum_sent);
}

/** get total values for this process */
void Process::gettotalkb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  *recvd = tokb(sum_recv);
  *sent = tokb(sum_sent);
}

void Process::gettotalb(float *recvd, float *sent) {
  u_int64_t sum_sent = 0, sum_recv = 0;
  gettotal(&sum_recv, &sum_sent);
  // std::cout << "Total sent: " << sum_sent << std::endl;
  *sent = sum_sent;
  *recvd = sum_recv;
}

/* For a connection that is about to "die" - we would like to obtain information about it! */
bool Process::matchConnection(Connection *del_conn)
{
  ConnSummary *node_iterator = conn_summary_list; // To iterate over all the Linked List elements
  //std::cout << "Trying to matchConnection" << std::endl;
  while (node_iterator!=NULL) // while we haven't reached the end of the Linked List
  {
    if (node_iterator->info.sa_family != del_conn->refpacket->getFamily())
    {
      node_iterator = node_iterator->next;
      continue;
    }
    if (node_iterator->info.sa_family == AF_INET)
    {
      if (sameinaddr(node_iterator->info.ip_src, del_conn->refpacket->sip) && sameinaddr(node_iterator->info.ip_dst, del_conn->refpacket->dip))
      {
	//std::cout << "Addresses are of the same IPv4 Type - Trying to update the Connection" << std::endl;
	updateConnection(node_iterator, del_conn);
	//std::cout << "A connection has been successfully updated at a matchConnection" << std::endl;
	return true;
      }
    }
    else if (node_iterator->info.sa_family == AF_INET6)
    {
      if (samein6addr(node_iterator->info.ip6_src, del_conn->refpacket->sip6) && samein6addr(node_iterator->info.ip6_dst, del_conn->refpacket->dip6))
      {
	//std::cout << "Addresses are of the same IPv4 Type - Trying to update the Connection" << std::endl;
	updateConnection(node_iterator, del_conn);
    //std::cout << "A connection has been successfully updated at a matchConnection" << std::endl;
	return true;
      }
    }
    node_iterator = node_iterator->next;
  }
  //std::cout << "matchConnection is finally over successfully - No match was found!" << std::endl;
  return false;
}

/* This function is called only in case we've found a match between a given connection that is timed out to a list of Hold Connection for a Process */
void Process::updateConnection(ConnSummary *node_connection, Connection *del_conn)
{
  //std::cout << "Trying to update a Connection" << std::endl;
  node_connection->total_sent+=del_conn->sumSent;
  node_connection->total_received+=del_conn->sumRecv;
  //std::cout << "Update of a connection is done successfully" << std::endl;
}


Process *findProcess(struct prg_node *node) {
  ProcList *current = processes;
  while (current != NULL) {
    Process *currentproc = current->getVal();
    assert(currentproc != NULL);

    if (node->pid == currentproc->pid)
      return current->getVal();
    current = current->next;
  }
  return NULL;
}


void Process::addToList(Connection *conn)
{
  ConnSummary *temp;
  if (!matchConnection(conn))
  {
    temp = conn_summary_list;
    if (temp == NULL) /* If that's the first one */
    {
	//std::cout << "Adding First Connection" << std::endl;
	conn_summary_list = (ConnSummary*)malloc(sizeof(struct conn_summary));
	//std::cout << "Alloaction has been done successfully" << std::endl;
	conn_summary_list->next = NULL;
	//std::cout << "Adding First Connection - Complete" << std::endl;
	setConnectionData(conn_summary_list,conn);
    }
    else
    {
      //std::cout << "Trying to add a Connection to the list" << std::endl;
      //std::cout << "Entering a while loop" << std::endl;
      while(temp->next != NULL)
      {
        temp = temp->next;
      }
      //std::cout << "Out of a while loop successfully" << std::endl;
      temp->next = (ConnSummary*)malloc(sizeof(ConnSummary));
      temp = temp -> next;
      temp->next = NULL;
      setConnectionData(temp,conn);
    }
  }
}

void Process::setConnectionData(ConnSummary *cur_conn, Connection *conn_to_update)
{
    if (conn_to_update->refpacket->getFamily() == AF_INET)
    {
      cur_conn->info.ip_src = conn_to_update->refpacket->sip;
      cur_conn->info.ip_dst = conn_to_update->refpacket->dip;
      cur_conn->info.sa_family = conn_to_update->refpacket->getFamily();
      cur_conn->total_sent = conn_to_update->sumSent;
      cur_conn->total_received = conn_to_update->sumRecv;
    }
    else if (conn_to_update->refpacket->getFamily() == AF_INET6)
    {
      cur_conn->info.ip6_src = conn_to_update->refpacket->sip6;
      cur_conn->info.ip6_dst = conn_to_update->refpacket->dip6;
      cur_conn->info.sa_family = conn_to_update->refpacket->getFamily();
      cur_conn->total_sent = conn_to_update->sumSent;
      cur_conn->total_received = conn_to_update->sumRecv;      
    }
    else std::cout << "NO IPv4 or IPv6 for a connection in process " << pid << std::endl;
}

/* finds process based on inode, if any */
/* should be done quickly after arrival of the packet,
 * otherwise findPID will be outdated */
Process *findProcess(unsigned long inode) {
  struct prg_node *node = findPID(inode);

  if (node == NULL)
    return NULL;

  return findProcess(node);
}

int ProcList::size() {
  int i = 1;

  if (next != NULL)
    i += next->size();

  return i;
}

void check_all_procs() {
  ProcList *curproc = processes;
  while (curproc != NULL) {
    curproc->getVal()->check();
    curproc = curproc->getNext();
  }
}

/*
 * returns the process from proclist with matching pid
 * if the inode is not associated with any PID, return NULL
 * if the process is not yet in the proclist, add it
 */
Process *getProcess(unsigned long inode, const char *devicename) {
  struct prg_node *node = findPID(inode);

  if (node == NULL) {
    if (DEBUG || bughuntmode)
      std::cout << "No PID information for inode " << inode << std::endl;
    return NULL;
  }

  Process *proc = findProcess(node);

  if (proc != NULL)
    return proc;

  // extract program name and command line from data read from cmdline file
  const char *prgname = node->cmdline.c_str();
  const char *cmdline = prgname + strlen(prgname) + 1;

  Process *newproc = new Process(inode, devicename, prgname, cmdline);
  newproc->pid = node->pid;

  char procdir[100];
  sprintf(procdir, "/proc/%d", node->pid);
  struct stat stats;
  int retval = stat(procdir, &stats);

  /* 0 seems a proper default.
   * used in case the PID disappeared while nethogs was running
   * TODO we can store node->uid this while info on the inodes,
   * right? */
  /*
  if (!ROBUST && (retval != 0))
  {
          std::cerr << "Couldn't stat " << procdir << std::endl;
          assert (false);
  }
  */

  if (retval != 0)
    newproc->setUid(0);
  else
    newproc->setUid(stats.st_uid);

  /*if (getpwuid(stats.st_uid) == NULL) {
          std::stderr << "uid for inode
          if (!ROBUST)
                  assert(false);
  }*/
  processes = new ProcList(newproc, processes);
  return newproc;
}

/*
 * Used when a new connection is encountered. Finds corresponding
 * process and adds the connection. If the connection  doesn't belong
 * to any known process, the process list is updated and a new process
 * is made. If no process can be found even then, it's added to the
 * 'unknown' process.
 */
Process *getProcess(Connection *connection, const char *devicename) {
  unsigned long inode = conninode[connection->refpacket->gethashstring()];

  if (inode == 0) {
    // no? refresh and check conn/inode table
    if (bughuntmode) {
      std::cout << "?  new connection not in connection-to-inode table before "
                   "refresh, hash "
                << connection->refpacket->gethashstring() << std::endl;
    }
// refresh the inode->pid table first. Presumably processing the renewed
// connection->inode table
// is slow, making this worthwhile.
// We take the fact for granted that we might already know the inode->pid
// (unlikely anyway if we
// haven't seen the connection->inode yet though).
#ifndef __APPLE__
    reread_mapping();
#endif
    refreshconninode();
    inode = conninode[connection->refpacket->gethashstring()];
    if (bughuntmode) {
      if (inode == 0) {
        std::cout << ":( inode for connection not found after refresh.\n";
      } else {
        std::cout << ":) inode for connection found after refresh.\n";
      }
    }
#if REVERSEHACK
    if (inode == 0) {
      /* HACK: the following is a hack for cases where the
       * 'local' addresses aren't properly recognised, as is
       * currently the case for IPv6 */

      /* we reverse the direction of the stream if
       * successful. */
      Packet *reversepacket = connection->refpacket->newInverted();
      inode = conninode[reversepacket->gethashstring()];

      if (inode == 0) {
        delete reversepacket;
        if (bughuntmode || DEBUG)
          std::cout << "LOC: " << connection->refpacket->gethashstring()
                    << " STILL not in connection-to-inode table - adding to "
                       "the unknown process\n";
        unknowntcp->connections =
            new ConnList(connection, unknowntcp->connections);
        return unknowntcp;
      }

      delete connection->refpacket;
      connection->refpacket = reversepacket;
    }
#endif
  } else if (bughuntmode) {
    std::cout
        << ";) new connection in connection-to-inode table before refresh.\n";
  }

  if (bughuntmode) {
    std::cout << "   inode # " << inode << std::endl;
  }

  Process *proc = NULL;
  if (inode != 0)
    proc = getProcess(inode, devicename);

  if (proc == NULL) {
    proc = new Process(inode, "", connection->refpacket->gethashstring());
    processes = new ProcList(proc, processes);
  }

  proc->connections = new ConnList(connection, proc->connections);
  return proc;
}

void procclean() {
  // delete conninode;
  prg_cache_clear();
}

void remove_timed_out_processes() {
  ProcList *previousproc = NULL;

  for (ProcList *curproc = processes; curproc != NULL;
       curproc = curproc->next) {
    if ((curproc->getVal()->getLastPacket() + PROCESSTIMEOUT <=
         curtime.tv_sec) &&
        (curproc->getVal() != unknowntcp) &&
        (curproc->getVal() != unknownudp) && (curproc->getVal() != unknownip)) {
      if (DEBUG)
        std::cout << "PROC: Deleting process\n";
      ProcList *todelete = curproc;
      Process *p_todelete = curproc->getVal(); // The Current Process
      if (previousproc) {
        previousproc->next = curproc->next;
        curproc = curproc->next;
      } else {
        processes = curproc->getNext();
        curproc = processes;
      }
      std::cout << "Removing Timeout Process : " << p_todelete->name << std::endl;
      delete todelete; // Calling 'ProcList' Destructor
      //plot_process_connections_summary(p_todelete);
      remove_process_connections_summary(p_todelete);
      delete p_todelete; // Calling current 'Process' Destructor
    }
    previousproc = curproc;
  }
}
/*
void plot_process_connections_summary(Process *proc)
{
  int connection_count;
  ConnSummary *cur = proc->conn_summary_list;
  char str[INET_ADDRSTRLEN];
  FILE *fout;
  fout = fopen("/home/vladi/nethogs_list.txt", "a"); // #TODO - make it generic
  if(!fout)
  {
    std::cout << "File is not open" << std::endl;
    return;
  }
  fprintf(fout,"AAAA\n");
  fprintf(fout,"---Procee Info---\n\n");
  fprintf(fout,"Process name = %s\n", proc->name);
  fprintf(fout,"Process devicename = %s\n", proc->devicename);
  fprintf(fout,"Process PID = %d\n", proc->pid);
  fprintf(fout,"Process UID = %d\n", proc->getUid());
  fprintf(fout,"Total Process Sent Bytes from closed connections = %d\n", proc->sent_by_closed_bytes);
  fprintf(fout,"Total Process Received Bytes from closed connections = %d\n", proc->rcvd_by_closed_bytes);
  fprintf(fout,"-------------------------------\n\n");
  fprintf(fout,"---Going over all Summary Connection Nodes--\n");

  for(connection_count = 1; cur != NULL; cur = cur->next)
  {
    fprintf(fout,"Connection Number %d\n", connection_count);
    if (cur->info.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &(cur->info.ip_src), str, INET_ADDRSTRLEN);
      fprintf(fout, "Source IP = %s\n", str);
      inet_ntop(AF_INET, &(cur->info.ip_dst), str, INET_ADDRSTRLEN);
      fprintf(fout, "Destination IP = %s\n", str);
    }
    else if (cur->info.sa_family == AF_INET6)
    {
      inet_ntop(AF_INET6, &(cur->info.ip6_src), str, INET_ADDRSTRLEN);
      fprintf(fout, "Source IP = %s\n", str);
      inet_ntop(AF_INET6, &(cur->info.ip6_dst), str, INET_ADDRSTRLEN);
      fprintf(fout, "Destination IP = %s\n", str);
    }
    fprintf(fout, "Bytes Sent = %d\n", cur->total_sent);
    fprintf(fout, "Bytes Received = %d\n", cur->total_received);
  }
  fprintf(fout,"All Summary Connection Nodes have been printed\n");
  ConnList *temp_con_list = proc->connections;
  Connection *conn;
  char str_src[INET_ADDRSTRLEN];
  char str_dest[INET_ADDRSTRLEN];

  while(temp_con_list)
  {
    conn = temp_con_list->getVal();
    inet_ntop(AF_INET, &(conn->refpacket->sip), str_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(conn->refpacket->dip), str_dest,INET_ADDRSTRLEN);
    fprintf(fout,"Not closed connection\nInfo:\nip_src: %s,\nip_dst: %s,\nsent: %d\n,recv: %d\n\n",str_src, str_dest, conn->sumSent, conn->sumRecv);
    temp_con_list = temp_con_list->getNext();
  }
  fprintf(fout,"All 'Still Opened Connections' of process with PID = %d have been printed!\n\n", proc->pid);
  fclose(fout);
}
*/
void remove_process_connections_summary(Process *p_todelete)
{
  ConnSummary *cur = p_todelete->conn_summary_list;
  ConnSummary *prev;
  while(cur != NULL)
  {
    prev = cur;
    cur = cur -> next;
    free(prev);
  }
}
