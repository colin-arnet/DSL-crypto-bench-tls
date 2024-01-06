.. 
   Copyright 2019 Xilinx, Inc.
  
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
  
       http://www.apache.org/licenses/LICENSE-2.0
  
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.


.. Project documentation master file, created by
   sphinx-quickstart on Tue Oct 30 18:39:21 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Vitis Graph Library
==========================

Vitis Graph Library is an open-sourced Vitis library written in C++ for accelerating graph applications in a variety of use cases. It now covers a level of acceleration: the pre-defined kernel level (L2), and will evolve to offer the module level (L1) and the software API level (L3).

Currently, this includes the following algorithm implementation:

 - Similarity analysis: Cosine Similarity, Jaccard Similarity, k-nearest Neighbor.
 - Centrality analysis: PageRank.
 - Pathfinding: Single Source Shortest Path (SSSP), Multi-Source Shortest Path (MSSP), Minimum Spanning Tree and Estimated Diameter.
 - Connectivity analysis: Weakly Connected Components and Strongly Connected Components.
 - Community Detection: Louvain Modularity (From 22.1, Louvain API can support large-scale graphs), Label Propagation and Triangle Count.
 - Search: Breadth First Search and 2-Hop Search.
 - Graph Format: Renumber, Calculate Degree and Format Convertion between CSR and CSC.


Shell Environment
------------------

Setup the build environment using the Vitis and XRT scripts.

.. ref-code-block:: bash
	:class: overview-code-block

        source <install path>/Vitis/2022.1/settings64.sh
        source /opt/xilinx/xrt/setup.sh
        export PLATFORM_REPO_PATHS=/opt/xilinx/platforms

Setting ``PLATFORM_REPO_PATHS`` to the installation folder of platform files can enable makefiles
in this library to use ``DEVICE`` variable as a pattern.
Otherwise, full path to .xpfm file needs to be provided via ``DEVICE`` variable.


.. toctree::
   :caption: Library Overview
   :maxdepth: 1

   overview.rst
   release.rst
   tutorial.rst

.. toctree::
   :caption: L1 User Guide
   :maxdepth: 3

   guide_L1/api.rst

.. toctree::
   :maxdepth: 2

   guide_L1/internals.rst

.. toctree::
   :caption: L2 User Guide
   :maxdepth: 3

   guide_L2/api.rst

.. toctree::
   :maxdepth: 2

   guide_L2/internals.rst

.. toctree::
   :caption: L3 User Guide
   :maxdepth: 4

   guide_L3/utilization_L3.rst

.. toctree::
   :maxdepth: 2

   guide_L3/api.rst

.. toctree::
   :caption: TigerGraph Plugin
   :maxdepth: 3

   plugin/tigergraph_integration.rst

.. toctree::
   :caption: Benchmark 
   :maxdepth: 1 

   benchmark.rst

Indices and tables
------------------

* :ref:`genindex`
* :ref:`search`
