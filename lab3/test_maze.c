#include <stdio.h>
#include <stdbool.h>

#define ROWS 5
#define COLS 5

char maze[ROWS][COLS] = {
    {'S', 'X', ' ', ' ', ' '},
    {' ', 'X', 'X', ' ', ' '},
    {' ', ' ', 'X', 'X', ' '},
    {' ', ' ', ' ', 'X', ' '},
    {' ', ' ', ' ', 'E', ' '}
};

bool visited[ROWS][COLS];

// Function to solve maze using DFS
bool solveMaze(int row, int col) {
    if (row < 0 || row >= ROWS || col < 0 || col >= COLS || maze[row][col] == 'X' || visited[row][col]) {
        return false;
    }

    visited[row][col] = true;

    if (maze[row][col] == 'E') {
        return true;
    }

    // Try moving right
    if (solveMaze(row, col + 1)) {
        return true;
    }
    // Try moving down
    if (solveMaze(row + 1, col)) {
        return true;
    }
    // Try moving left
    if (solveMaze(row, col - 1)) {
        return true;
    }
    // Try moving up
    if (solveMaze(row - 1, col)) {
        return true;
    }

    // If no path found, backtrack
    visited[row][col] = false;
    return false;
}

int main() {
    int startRow, startCol;
    // Find the starting point
    for (int i = 0; i < ROWS; i++) {
        for (int j = 0; j < COLS; j++) {
            if (maze[i][j] == 'S') {
                startRow = i;
                startCol = j;
                break;
            }
        }
    }

    if (solveMaze(startRow, startCol)) {
        // Print solved maze with correct route
        for (int i = 0; i < ROWS; i++) {
            for (int j = 0; j < COLS; j++) {
                if (visited[i][j]) {
                    printf(". ");
                } else {
                    printf("%c ", maze[i][j]);
                }
            }
            printf("\n");
        }
    } else {
        printf("No solution found!\n");
    }

    return 0;
}
