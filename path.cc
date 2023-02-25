
/*
 * path.cc
 * Copyright (C) 2000 by the University of Southern California
 * $Id: path.cc,v 1.7 2005/08/25 18:58:05 johnh Exp $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * The copyright of this module includes the following
 * linking-with-specific-other-licenses addition:
 *
 * In addition, as a special exception, the copyright holders of
 * this module give you permission to combine (via static or
 * dynamic linking) this module with free software programs or
 * libraries that are released under the GNU LGPL and with code
 * included in the standard release of ns-2 under the Apache 2.0
 * license or under otherwise-compatible licenses with advertising
 * requirements (or modified versions of such code, with unchanged
 * license).  You may copy and distribute such a system following the
 * terms of the GNU GPL for this module and the licenses of the
 * other code concerned, provided that you include the source code of
 * that other code when and as the GNU GPL requires distribution of
 * source code.
 *
 * Note that people who make modified versions of this module
 * are not obligated to grant this special exception for their
 * modified versions; it is their choice whether to do so.  The GNU
 * General Public License gives permission to release a modified
 * version without this exception; this exception also makes it
 * possible to release a modified version which carries forward this
 * exception.
 *
 */
//
// Other copyrights might apply to parts of this software and are so
// noted when applicable.
//
// Ported from CMU/Monarch's code, appropriate copyright applies.

/* path.cc

   handles source routes

*/

extern "C"
{
#include <assert.h>
#include <stdio.h>

}

#include <packet.h>
#include <ip.h>
#include "hdr_sr.h"
#include "path.h"

/*===========================================================================
  global statics
---------------------------------------------------------------------------*/

ID invalid_addr(0xffffffff, ::NONE);
ID IP_broadcast(IP_BROADCAST, ::IP);

/*===========================================================================
  ID methods
---------------------------------------------------------------------------*/
void ID::unparse(FILE *out) const
{
  fprintf(out, "%d", (int)addr);
}

char *
ID::dump() const
{
  static char buf[MAX_SR_LEN + 1][50];
  static int which = 0;
  char *ptr = buf[which];
  which = (which + 1) % (MAX_SR_LEN + 1);

  assert(type == ::NONE || type == ::MAC || type == ::IP);

  if (type == ::IP)
    sprintf(ptr, "%d", (int)addr);
  else if (type == ::NONE)
    sprintf(ptr, "NONE");
  else
    sprintf(ptr, "0x%x", (int)addr);
  return ptr;
}

/*===========================================================================
  Path methods
---------------------------------------------------------------------------*/
/* rep invariants:
   -1 <= cur_index <= len  (neither bound is really hard)
   0 <= len < MAX_SR_LEN
*/

Path::Path(int route_len, const ID *route)
{
  path = new ID[MAX_SR_LEN];
  min_energy = new double[MAX_SR_LEN];
  hop_distance = new double[MAX_SR_LEN] ;
  assert(route_len <= MAX_SR_LEN);
  //  route_len = (route == NULL : 0 ? route_len);
  // a more cute solution, follow the above with the then clause
  min_energy[0] = inf;
  hop_distance[0] = 0.0 ;
  if (route != NULL)
  {
    for (int c = 0; c < route_len; c++)
    {
      path[c] = route[c];
      min_energy[c] = (c>0) ? min(min_energy[c-1],route[c].node_energy) : route[c].node_energy ;
    }
    for(int c=1;c<route_len;c++){
      hop_distance[c] = hop_distance[c-1] + euclidean_distance(c,c-1); /* sqrt( (path[c].pos_x-path[c+1].pos_x)*(path[c].pos_x-path[c+1].pos_x) 
                            + (path[c].pos_y-path[c+1].pos_y)*(path[c].pos_y-path[c+1].pos_y)
                            + (path[c].pos_z-path[c+1].pos_z)*(path[c].pos_z-path[c+1].pos_z) ); */
    }
    len = route_len;
  }
  else
  {
    len = 0;
  }
  cur_index = 0;
}

Path::Path()
{
  path = new ID[MAX_SR_LEN];
  hop_distance = new double[MAX_SR_LEN];
  min_energy = new double[MAX_SR_LEN];
  hop_distance[0] = 0.0;
  min_energy[0] = inf; 
  len = 0;
  cur_index = 0;
}

Path::Path(const struct sr_addr *addrs, int len)
{ /* make a path from the bits of an NS source route header */
  assert(len <= MAX_SR_LEN);
  path = new ID[MAX_SR_LEN];
  hop_distance = new double[MAX_SR_LEN];
  min_energy = new double[MAX_SR_LEN];
  hop_distance[0] = 0.0;
  min_energy[0] = inf; 
  for (int i = 0; i < len; i++){
    path[i] = ID(addrs[i]);
    min_energy[i] = (i>0) ? min(min_energy[i-1],path[i].node_energy) : path[i].node_energy ;
  }
  for( int c=1;c<len;c++){
    hop_distance[c] = hop_distance[c-1] + euclidean_distance(c,c-1); /* sqrt( (path[c].pos_x-path[c+1].pos_x)*(path[c].pos_x-path[c+1].pos_x) */ 
  }
  this->len = len;
  cur_index = 0;
}

Path::Path(struct hdr_sr *srh)
{ /* make a path from the bits of an NS source route header */
  path = new ID[MAX_SR_LEN];
  hop_distance = new double[MAX_SR_LEN];
  min_energy = new double[MAX_SR_LEN];
  hop_distance[0] = 0.0;
  min_energy[0] = inf; 
  if (!srh->valid())
  {
    len = 0;
    cur_index = 0;
    return;
  }

  len = srh->num_addrs();
  cur_index = srh->cur_addr();

  assert(len <= MAX_SR_LEN);

  for (int i = 0; i < len; i++){
    path[i] = ID(srh->addrs()[i]);
    min_energy[i] = (i>0) ? min(min_energy[i-1],path[i].node_energy) : path[i].node_energy ;
  }
  for( int c=1;c<len;c++){
    hop_distance[c] = hop_distance[c-1] + euclidean_distance(c,c-1); /* sqrt( (path[c].pos_x-path[c+1].pos_x)*(path[c].pos_x-path[c+1].pos_x) */ 
  }
}

void Path::fillSR(struct hdr_sr *srh)
{
  for (int i = 0; i < len; i++)
  {
    path[i].fillSRAddr(srh->addrs()[i]);
  }
  hop_distance[0] = 0.0;
  min_energy[0] = inf; 
  for (int i = 0; i < len; i++){
    min_energy[i] = (i>0) ? min(min_energy[i-1],path[i].node_energy) : path[i].node_energy ;
  }
  for( int c=1;c<len;c++){
    hop_distance[c] += hop_distance[c-1] + euclidean_distance(c,c-1); /* sqrt( (path[c].pos_x-path[c+1].pos_x)*(path[c].pos_x-path[c+1].pos_x) */ 
  }
  srh->num_addrs() = len;
  srh->cur_addr() = cur_index;
}

Path::Path(const Path &old)
{
  path = new ID[MAX_SR_LEN];
  hop_distance = new double[MAX_SR_LEN];
  min_energy = new double[MAX_SR_LEN]; 
 
  // hop_distance[0] = 0.0;
  // min_energy[0] = inf; 
  
  if (old.path != NULL)
  {
    for (int c = 0; c < old.len; c++){
      path[c] = old.path[c];
      min_energy[c] = old.min_energy[c] ;
      hop_distance[c] = old.hop_distance[c] ;
    }
    len = old.len;
  }
  else
  {
    len = 0;
    min_energy[0] = inf; 
    hop_distance[0] = 0.0 ;
  }
  cur_index = old.cur_index;
  path_owner = old.path_owner;
}

Path::~Path()
{
  delete[] path; delete [] min_energy ;
  delete [] hop_distance ;
}

void Path::operator=(const Path &rhs)
// makes the lhs a copy of the rhs: lhs may share data with
// the rhs such that changes to one will be seen by the other
// use the provided copy operation if you don't want this.
{
  /* OLD  NOTE:
    we save copying the path by doing a delete[] path; path = rhs.path;
     but then the following code will be fatal (it calls delete[]
     twice on the same address)
       { Path p1();
         { Path p2();
           p2 = p1;
         }
       }
     you'd have to implement reference counts on the path array to
     save copying the path.

     NEW NOTE: we just copy like everything else
  */
  if (this != &rhs)
  { // beware of path = path (see Stroustrup p. 238)
    cur_index = rhs.cur_index;
    path_owner = rhs.path_owner;
    len = rhs.len;
    for (int c = 0; c < len; c++) {
      path[c] = rhs.path[c];
      min_energy[c] = rhs.min_energy[c];
      hop_distance[c] = rhs.hop_distance[c] ;
    }
  }
  // note: i don't return *this cause I don't think assignments should
  // be expressions (and it has slightly incorrect semantics: (a=b) should
  // have the value of b, not the new value of a)
}

bool Path::operator==(const Path &rhs)
{
  int c;
  if (len != rhs.len)
    return false;
  for (c = 0; c < len; c++)
    if (path[c] != rhs.path[c])
      return false;
  return true;
}
void Path::appendPath(Path &p)
{
  int i;
  for (i = 0; i < p.length(); i++)
  {
    path[len] = p[i];
    len++;
    if (len > MAX_SR_LEN)
    {
      fprintf(stderr, "DFU: overflow in appendPath len2 %d\n",
              p.length());
      len--;
      return;
    }
// add energy and distance infromation 
    min_energy[i] = (i>0) ? min(min_energy[i-1],p[i].node_energy) : p[i].node_energy; 
    hop_distance[i] = (i>0) ? euclidean_distance(i,i-1)+hop_distance[i-1] : 0.0 ;
  }
}

void Path::removeSection(int from, int to)
// the elements at indices from -> to-1 are removed from the path
{
  int i, j;

  if (to <= from)
    return;
  if (cur_index > from)
    cur_index = cur_index - (to - from);
  for (i = to, j = 0; i < len; i++, j++)
    path[from + j] = path[i];
  len = from + j;
}

Path Path::copy() const
{
  Path p(len, path);
  p.cur_index = cur_index;
  p.path_owner = path_owner;
  return p;
}

void Path::copyInto(Path &to) const
{
  to.cur_index = cur_index;
  to.len = len;
  for (int c = 0; c < len; c++){
    to.path[c] = path[c];
    to.min_energy[c] = min_energy[c] ;
    to.hop_distance[c] = hop_distance[c] ;
  }
  to.path_owner = path_owner;
}

Path Path::reverse() const
// return an identical path with the index pointing to the same
// host, but the path in reverse order
{
  if (len == 0)
    return *this;
  Path p;

  int from, to;
  for (from = 0, to = (len - 1); from < len; from++, to--)
    p.path[to] = path[from];
  p.len = len;
  p.cur_index = (len - 1) - cur_index;
  
  p.min_energy[0] = inf; 
  p.hop_distance[0] = 0.0 ;
  for (int i = 0; i < len; i++){
    p.min_energy[i] = (i>0) ? min(p.min_energy[i-1],p.path[i].node_energy) : p.path[i].node_energy ;
  }
  for( int c=1;c<len;c++){
    p.hop_distance[c] = p.hop_distance[c-1] + p.euclidean_distance(c,c-1); /* sqrt( (path[c].pos_x-path[c+1].pos_x)*(path[c].pos_x-path[c+1].pos_x) */ 
  }
  return p;
}

void Path::reverseInPlace()
{
  if (len == 0)
    return;
  int fp, bp; // forward ptr, back ptr
  ID temp;
  for (fp = 0, bp = (len - 1); fp < bp; fp++, bp--)
  {
    temp = path[fp];
    path[fp] = path[bp];
    path[bp] = temp;
  }
  cur_index = (len - 1) - cur_index;
  
  min_energy[0] = inf; 
  hop_distance[0] = 0.0 ;
  for (int i = 0; i < len; i++){
    min_energy[i] = (i>0) ? min(min_energy[i-1],path[i].node_energy) : path[i].node_energy ;
  }
  for( int c=1;c<len;c++){
    hop_distance[c] = hop_distance[c-1] + euclidean_distance(c,c-1); /* sqrt( (path[c].pos_x-path[c+1].pos_x)*(path[c].pos_x-path[c+1].pos_x) */ 
  }
}

int Path::size() const
{
  // this should be more clever and ask the id's what their sizes are.
  return len * 4;
}

bool Path::member(const ID &id) const
// rtn true iff id is in path
{
  return member(id, invalid_addr);
}

bool Path::member(const ID &id, const ID &MAC_id) const
// rtn true iff id or MAC_id is in path
{
  for (int c = 0; c < len; c++)
    if (path[c] == id || path[c] == MAC_id)
      return true;
  return false;
}

void Path::unparse(FILE *out) const
{
  // change to put ()'s around the cur_index entry?
  if (len == 0)
  {
    fprintf(out, "<empty path>");
    return;
  }
  for (int c = 0; c < len - 1; c++)
  {
    if (c == cur_index)
      fprintf(out, "(");
    path[c].unparse(out);
    if (c == cur_index)
      fprintf(out, ")");
    fprintf(out, ",");
  }
  if (len - 1 == cur_index)
    fprintf(out, "(");
  path[len - 1].unparse(out);
  if (len - 1 == cur_index)
    fprintf(out, ")");
}

char *
Path::dump() const
{
  static int which = 0;
  static char buf[4][100];
  char *ptr = buf[which];
  char *rtn_buf = ptr;
  which = (which + 1) % 4;

  if (len == 0)
  {
    sprintf(rtn_buf, "[<empty path>]");
    return rtn_buf;
  }
  *ptr++ = '[';
  for (int c = 0; c < len; c++)
  {
    if (c == cur_index)
      *ptr++ = '(';
    ptr += sprintf(ptr, "%s%s ", path[c].dump(), c == cur_index ? ")" : "");
  }
  *ptr++ = ']';
  *ptr++ = '\0';
  return rtn_buf;
}

double 
Path::path_cost() {
  return (len>0) ? cost_func(min_energy[len-1], hop_distance[len-1], len) : cost_func(0.0,0.0,len); 
}

double 
Path::path_cost(int i,int j) {
  assert( i>0 && i<len && j>0 && j<len && i<=j ) ; 
  double e=inf,ed=0.0;
  e= min_energy[j];
  ed = hop_distance[j]-hop_distance[i];

  return (len>0) ? cost_func(e,ed,len) : cost_func(0,0,len);  
}
void 
Path::recalc_metrics(int i ){
  assert(i<len) ;
  if( !i ){
    hop_distance[i]=0;
    min_energy[i]=path[i].node_energy;
  }
  else {
    hop_distance[i]=hop_distance[i-1]+euclidean_distance(i,i-1) ;
    min_energy[i]=min(min_energy[i-1],path[i].node_energy) ;
  } 
}

void compressPath(Path &path)
// take a path and remove any double backs from it
// eg:  A B C B D --> A B D
{
  // idea: walk one pointer from begining
  //  for each elt1 start at end of path and walk a pointer backwards (elt2)
  //   if forward pointer = backward pointer, go on and walk foward one more
  //   if elt1 = elt2 then append {(elt2 + 1) to end} after forward pointer
  //    update length of path (we just cut out a loopback) and walk forward
  //  when forward walking pointer reaches end of path we're done

  int fp = 0, bp; // the forward walking ptr and the back walking ptr
  while (fp < path.len)
  {
    for (bp = path.len - 1; bp != fp; bp--)
    {
      if (path.path[fp] == path.path[bp])
      {
        int from, to;
        for (from = bp, to = fp;
             from < path.len;
             from++, to++)
          path.path[to] = path.path[from];
        path.len = to;
        break;
      }   // end of removing double back
    }     // end of scaning to check for double back
    fp++; // advance the forward moving pointer
  }
}

void CopyIntoPath(Path &to, const Path &from, int start, int stop)
// sets to[0->(stop-start)] = from[start->stop]
{
  assert(start >= 0 && stop < from.len);
  int f, t, c; // from and to indices
  for (f = start, t = 0; f <= stop; f++, t++)
    to.path[t] = from.path[f];
  if (to.len < stop - start + 1)
    to.len = stop - start + 1;
  for (c = to.len - 1; c >= 0; c--)
  {
    if (to.path[c] == to.owner())
      break;
    if (to.path[c] == ((Path &)from).owner())
    {
      to.owner() = ((Path &)from).owner();
      break;
    }
  }
}

void Path::checkpath() const
{
  for (int c = 0; c < MAX_SR_LEN; c++)
  {
    assert(path[c].type == NONE ||
           path[c].type == MAC ||
           path[c].type == IP);
  }
}

int compare(Path &lhs,int l_len, Path &rhs, int r_len ){
  assert( l_len < lhs.length() && r_len < rhs.length() ) ; 
  return lhs.path_cost(0,l_len) > rhs.path_cost(0,r_len) ;

  double e1=1e18,e2=1e18,ed1=0.0,ed2=0.0 ;

  e1 = lhs.minimum_energy(l_len);
  e2 = rhs.minimum_energy(r_len) ;
  ed1 = lhs.total_distance(l_len); 
  ed2 = rhs.total_distance(r_len) ;
  
  e1 = (e1 == 1e18) ? 0.0 : e1;
  e2 = (e2 == 1e18) ? 0.0 : e2;

  if( e1 <= Path::energy_threshold ) 
    return 1; 
  if( e2 <= Path::energy_threshold ) 
    return 0 ;
  
  if( l_len < r_len )
    return 0; 
  if( l_len > r_len ) 
    return 1; 
  // if( 1000.0*e1-ed1 > 1000.0*e2-ed2 ) 
  //   return 0 ;
  // if( 1000.0*e1-ed1 < 1000.0*e2-ed2 ) 
    // return 1;
  if( e1 > e2 ) 
    return 0 ;
  if( e1 < e2 ) 
    return 1;  
  if( ed1 < ed2 ) 
    return 0 ;
  if (ed1 > ed2 ) 
    return 1; 
  return 1 ;
}