# -*- coding: utf-8 -*-
"""
Scalable Computing - Project 3
Group 21

Forwarding Information Base Class

Stores following information about peers in the network:
- Address as tuple of IP address and port
- Distance vectors to other peers in network

Authors: Kim Nolle (23345045)
"""

# Imports
import pandas as pd
import numpy as np


class ForwardingInfoBase:

    def __init__(self, node_name):
        """
        Parameters
        ----------
        node_name : str
            Name of the node to which this FIB belongs to.

        Returns
        -------
        None.

        """
        self.name = node_name
        self.peer_list = {}
        self.dv_table = self._init_distance_vector()

    # Public Methods:
        
    def __contains__(self, item):
        return item in self.peer_list

    def add_entry(self, node_name, node_addr):
        """
        Add a neighbouring peer to the FIB.

        Parameters
        ----------
        node_name : str
            Name of the peer to add.
        node_addr : (str, int)
            Address of the peer as a tuple of IP address and port number.

        Returns
        -------
        bool
            Returns True if distance vector changed.
            (Note: This always returns true and is kept for consistency)

        """
        self.peer_list[node_name] = node_addr
        self._add_peer_to_distance_vector(node_name, set_as_nbr=True)
        dv_changed = self._calculate_distance_vector()
        
        return True

    def remove_entry(self, node_name):
        """
        Remove a neighbouring peer from the FIB

        Parameters
        ----------
        node_name : str
            Name of the peer to remove.

        Returns
        -------
        bool
            Returns True if distance vector changed.
            (Note: This always returns true and is kept for consistency)

        """
        del self.peer_list[node_name]
        self._drop_peer_from_distance_vector(node_name)
        dv_changed = self._calculate_distance_vector()
        
        return True

    def update_distance_vector(self, node_name, node_vector):
        """
        Update the FIB with a new distance vector from a neighbouring node.
        The of the neighbour distance vector is overwritten by the new one 
        and then the own distance vector is recalculated.

        Parameters
        ----------
        node_name : str
            Name of the peer that the vector belongs to.
        node_vector : dict(str, float)
            Distance vector belonging the neighbour.

        Returns
        -------
        dv_changed : bool
            Returns True if own distance vector changed.

        """
        self._update_peer_distance_vector(node_name, node_vector)
        dv_changed = self._calculate_distance_vector()
        
        return dv_changed

    def get_routes(self, data_name):
        """
        Get routes that lead to data_name. Returns a list of addresses in order
        of longest prefix matches and shortest number of hops.

        Parameters
        ----------
        data_name : str
            Name of data that should be matched to a node.

        Returns
        -------
        addr_to_try : List[(str, int)]
            List of address of the peer as a tuple of IP address and port number.

        """
        # Distance vector to neighbours
        dist_nbr = self.dv_table[[idx in self.peer_list.keys() for idx in self.dv_table.index]][self.name]
        
        # Add / to end of name to get correct matching
        dist_nbr_fmt = dist_nbr.add_suffix('/')
        
        # Use a copy of peer list to keep track of which peers have already been identified as routes
        peer_list_cpy = self.peer_list.copy()
        
        # Get list of addresses in order of longest prefix matches and shortest hops
        addr_to_try = []
        split = data_name.split('/')
        for i in range(0, len(split)):
            # Get prefix of data name to check for
            prefix = '/'.join(split[:len(split)-i])
            if not prefix.endswith('/'):
                prefix += '/'
                
            # Otherwise would select all the nodes starting with '/' as addresses to try
            if prefix == '/':
                break
        
            # Sort in ascending order by number of hops
            for index, value in dist_nbr[dist_nbr_fmt.index.str.startswith(prefix)].sort_values().items():
                # Get from peer list and add to results list
                addr = peer_list_cpy.pop(index, None)
                if addr is not None:
                    addr_to_try.append((index, addr))
                if not peer_list_cpy:
                    break
                    
            if not peer_list_cpy:
                    break
        
        return addr_to_try
    
    def get_distance_vector(self):
        return self.dv_table[self.name].to_dict()
    
    def get_peers(self):
        return self.peer_list.keys()
    
    # -------------------------------------------------------------------------
    # Private Methods:
    
    def _init_distance_vector(self):
        """
        Initialises the distance vector table with this node as the single entry.

        Returns
        -------
        pd.DataFrame
            Initialised distance vector table.
        """
        return pd.DataFrame(columns=[self.name], index=[self.name], data=[[0]])

    def _calculate_distance_vector(self):
        """
        Performs the Bellman-Ford algorithm to determine the node's distance vector.

        Returns
        -------
        bool
            States whether the distance vector of this node changed.

        """
        # Costs to neighbours in peer list is 1
        # Costs to self is 0
        # All other costs are inf
        cost = pd.Series(data=np.concatenate([[0], np.ones(len(self.peer_list.keys()))]), 
                  index=[self.name]+list(self.peer_list.keys()), 
                  name='cost')
        
        # Bellman-Ford Algorithm
        dv = []
        for node, distance in self.dv_table.iterrows():
            tmp = pd.concat([cost, distance], axis=1).fillna(np.inf)
            dv.append(min(tmp['cost'] + tmp[node]))
        self.dv_table[self.name] = dv
        
        return dv != list(cost)

    def _add_peer_to_distance_vector(self, name, set_as_nbr=False):
        """
        Adds a new node to the distance vector table with all distances initialised
        as inf. If a node is considered as a neighbour, then the distance between 
        this node and the new node is set to 1 hop.

        Parameters
        ----------
        name : str
            Name of the node to add to the table.
        set_as_nbr : bool, optional
            Whether to consider the new node as a direct neighbour.
            The default is False.

        Returns
        -------
        None.

        """
        self.dv_table[name] = np.inf
        self.dv_table.loc[name] = np.inf
    
        # Set distance of node to itself as 0
        self.dv_table.loc[name, name] = 0
        
        if set_as_nbr:
            self.dv_table.loc[self.name, name] = 1
            self.dv_table.loc[name, self.name] = 1

    def _drop_peer_from_distance_vector(self, name):
        """
        Remove node from distance vector

        Parameters
        ----------
        name : str
            Name of the node to remove.

        Returns
        -------
        None.

        """
        self.dv_table = self.dv_table.drop(index=[name], columns=[name], errors='ignore')

    def _update_peer_distance_vector(self, peer_name, peer_vector):
        """
        Overwrites distance vector of peer with new vector

        Parameters
        ----------
        peer_name : str
            Name of the node to update.
        peer_vector : dict[str, int]
            New distance vector of the peer.

        Returns
        -------
        None.

        """
        # Add missing nodes to table
        vector = pd.Series(peer_vector, name=peer_name)
        for node in set(vector.index) - set(self.dv_table.index):
            self._add_peer_to_distance_vector(node)
        
        # Replace distance vector in table with new distance vector
        self.dv_table = self.dv_table.drop(columns=[peer_name], errors='ignore')
        self.dv_table = pd.concat([self.dv_table, vector], axis=1).fillna(np.inf)