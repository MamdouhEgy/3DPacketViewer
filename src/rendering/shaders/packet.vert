#version 120
attribute vec3 position;
attribute vec3 color;
uniform mat4 mvp;
varying vec3 faceColor;
void main() { gl_Position = mvp * vec4(position, 1.0); faceColor = color; }
