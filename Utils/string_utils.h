//
// Created by Fermin Gomez on 6/15/19.
//

#ifndef PROBANDOTPPROTOS_STRING_UTILS_H
#define PROBANDOTPPROTOS_STRING_UTILS_H

/*
 * Copia el string apuntado por src en dst agregando el '\0' final en dst
 */
void
strncpy_(char *dst, char *src, int srcsize, int dstsize);

#endif //PROBANDOTPPROTOS_STRING_UTILS_H
