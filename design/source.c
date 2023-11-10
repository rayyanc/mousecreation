#include <stdio.h>

// Define mouse structure
struct Mouse {
    int x;
    int y;
    int buttons;
};

// Function to initialize the mouse
void initializeMouse(struct Mouse* mouse) {
    mouse->x = 0;
    mouse->y = 0;
    mouse->buttons = 0;
}

// Function to update mouse position
void updateMousePosition(struct Mouse* mouse, int newX, int newY) {
    mouse->x = newX;
    mouse->y = newY;
}

// Function to handle mouse button press
void handleMousePress(struct Mouse* mouse, int button) {
    mouse->buttons |= (1 << button);
}

// Function to handle mouse button release
void handleMouseRelease(struct Mouse* mouse, int button) {
    mouse->buttons &= ~(1 << button);
}

// Function to handle mouse movement
void handleMouseMove(struct Mouse* mouse, int deltaX, int deltaY) {
    mouse->x += deltaX;
    mouse->y += deltaY;
}

// Function to print mouse state
void printMouseState(struct Mouse* mouse) {
    printf("Mouse state - X: %d, Y: %d, Buttons: %d\n", mouse->x, mouse->y, mouse->buttons);
}

int main() {
    // Create a mouse instance
    struct Mouse myMouse;

    // Initialize the mouse
    initializeMouse(&myMouse);

    // Simulate mouse events
    updateMousePosition(&myMouse, 10, 20);
    handleMousePress(&myMouse, 0); // Press left button
    handleMousePress(&myMouse, 2); // Press right button
    printMouseState(&myMouse);

    // Update mouse position and release left button
    handleMouseMove(&myMouse, 5, 10); // Move the mouse
    handleMouseRelease(&myMouse, 0); // Release left button
    printMouseState(&myMouse);

    return 0;
}
