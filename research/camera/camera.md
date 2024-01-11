#General
The Optical Mouse utilizes a light-emitting object and a optoelectronic sensor (camera) to track the surface on which a mouse may operate. Usually either a LED or an infrared laser diode to cast shadows on the surface, so that the camera will store the images of these silhouettes it captures and compares them against each other to map the surface and determine in what direction and the speed of which the mouse is in motion.

#Optical Flow
The pattern of the motion of the surface under the mouse is decided relatively. The mouse compares the data of the two photographs it takes and shifts them across certain axis' until they line up. The amount that the edges of one photograph overhang the other represents their offset, and the x and y coordinates provided by this method decides on the movement of the cursor.
See the equations for this process over at: [Wikipedia: Optical flow](https://en.wikipedia.org/wiki/Optical_flow)

An Image Acquisition System and DSP processors are required for fast data processing of this method.

#Statistics
Usually, optical mice capture over 1000 images per second. Thus, depending on how fast the mice is being moved, offsets can be smaller than a fraction of a pixel, or can take up several pixels. 

#Weaknesses
##Surface Material
Because the camera is taking pictures of the surface of the material underneath the mouse, it has difficulty tracking glossy or transparent surfaces.

##Speed
Mice with less image-processing power have issues keeping track of fast movement. In comparison, high-quality mouses can track movement faster than 2 m/s.
